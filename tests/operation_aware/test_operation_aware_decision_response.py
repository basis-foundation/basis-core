"""
tests/operation_aware/test_operation_aware_decision_response.py — tests for
`basis_core.evaluation.operation_aware.response.OperationAwareDecisionResponse`
(Milestone 10, PR 29 of
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`:
"OperationAwareDecisionResponse model").

Covers `OperationAwareDecisionResponse` construction, validation, the
published required-key/nullable-key distinctions, the completed/failed
evaluation-state invariant, the narrow, fixture-driven response/trace
agreement subset this PR enforces (see `response.py`'s module docstring for
exactly which four clauses, and why the rest are deferred to PR 32),
immutability, boundedness, and serialization — cross-checked against every
vendored `basis-schemas` v0.2.1 `operation-aware-decision-response` contract
example (5 valid, 16 invalid) via the existing test-only loader
(`tests/helpers/operation_aware_contracts.py`).

This file tests response *shape* only: construction, validation,
immutability, and schema alignment. It does not test, and must never test,
response assembly from an `EvaluationTrace`/engine result (PR 31),
`AuditEvidence` (PR 30), or full response/trace/audit-evidence agreement
beyond the narrow subset `response.py` itself enforces (PR 32).
`TestV01Compatibility` is the mandatory, mechanically-checked proof that
`basis_core.decisions.models.DecisionResponse` (the existing v0.1.0 type) is
unaffected by anything added here.
"""

from __future__ import annotations

import json

import pytest
from pydantic import BaseModel, ValidationError

from basis_core.audit.operation_aware.evaluation_trace import EvaluationTrace
from basis_core.decisions.operation_aware import (
    OperationAwareDecisionOutcome,
    OperationAwareEvaluationStatus,
    OperationAwareFailureReason,
)
from basis_core.evaluation.operation_aware.response import OperationAwareDecisionResponse
from tests.helpers.operation_aware_contracts import (
    load_contract,
    require_mapping_field,
    require_sequence_field,
)

# ══════════════════════════════════════════════════════════════════════════
# Fixture loading
# ══════════════════════════════════════════════════════════════════════════


def _response_examples() -> tuple[list[object], list[object]]:
    document = load_contract("operation-aware-decision-response")
    section = require_mapping_field(
        document, "operation_aware_decision_response", context="operation-aware-decision-response"
    )
    examples = require_mapping_field(
        section,
        "examples",
        context="operation-aware-decision-response.operation_aware_decision_response",
    )
    valid = require_sequence_field(
        examples, "valid", context="operation-aware-decision-response.examples"
    )
    invalid = require_sequence_field(
        examples, "invalid", context="operation-aware-decision-response.examples"
    )
    return valid, invalid


_VALID_EXAMPLES, _INVALID_EXAMPLES = _response_examples()


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
        request_id = example.get("request_id")
        if isinstance(request_id, str) and request_id:
            return request_id
    return f"example-{index}"


# Minimal structurally valid records reused across tests that need one but
# are not themselves testing the field under test.
_MINIMAL_COMPLETED_ALLOW_KWARGS: dict[str, object] = {
    "request_id": "oadr-test-completed-allow",
    "evaluation_status": "completed",
    "outcome": "allow",
    "failure_reason": None,
}

_MINIMAL_FAILED_KWARGS: dict[str, object] = {
    "request_id": "oadr-test-failed",
    "evaluation_status": "failed",
    "outcome": None,
    "failure_reason": "internal_evaluation_error",
}

_MINIMAL_TRACE_KWARGS: dict[str, object] = {
    "trace_id": "trace-test-completed-allow",
    "request_id": "oadr-test-completed-allow",
    "evaluation_status": "completed",
    "outcome": "allow",
    "bundle_applicability": "applicable",
    "rule_evidence": [],
}


# ══════════════════════════════════════════════════════════════════════════
# Fixture conformance — every vendored valid/invalid example
# ══════════════════════════════════════════════════════════════════════════


class TestFixtureConformance:
    def test_five_valid_examples_are_vendored(self) -> None:
        assert len(_VALID_EXAMPLES) == 5

    def test_sixteen_invalid_examples_are_vendored(self) -> None:
        assert len(_INVALID_EXAMPLES) == 16

    @pytest.mark.parametrize(
        "example",
        _VALID_EXAMPLES,
        ids=[_valid_example_id(ex, i) for i, ex in enumerate(_VALID_EXAMPLES)],
    )
    def test_valid_example_constructs(self, example: object) -> None:
        assert isinstance(example, dict)
        response = OperationAwareDecisionResponse.model_validate(example)
        assert type(response) is OperationAwareDecisionResponse

    @pytest.mark.parametrize(
        "entry",
        _INVALID_EXAMPLES,
        ids=[_invalid_example_reason(ex, i) for i, ex in enumerate(_INVALID_EXAMPLES)],
    )
    def test_invalid_example_is_rejected(self, entry: object) -> None:
        value = _invalid_example_value(entry)
        with pytest.raises(ValidationError):
            OperationAwareDecisionResponse.model_validate(value)

    @pytest.mark.parametrize(
        "example",
        _VALID_EXAMPLES,
        ids=[_valid_example_id(ex, i) for i, ex in enumerate(_VALID_EXAMPLES)],
    )
    def test_all_vendored_valid_examples_round_trip(self, example: object) -> None:
        assert isinstance(example, dict)
        response = OperationAwareDecisionResponse.model_validate(example)
        dumped = response.model_dump(mode="json", exclude_none=True)
        restored = OperationAwareDecisionResponse.model_validate(dumped)
        assert restored == response

    def test_no_example_is_silently_skipped(self) -> None:
        # Every valid/invalid example is exercised by the two parametrized
        # tests above (their `ids=` lists are derived from the same
        # `_VALID_EXAMPLES`/`_INVALID_EXAMPLES` lists this test also
        # inspects) — this is a supplementary guard against a future edit
        # accidentally decoupling the parametrize list from the fixture.
        assert len(_VALID_EXAMPLES) + len(_INVALID_EXAMPLES) == 21

    def test_allow_with_embedded_trace_example_serializes_expected_shape(self) -> None:
        example = _VALID_EXAMPLES[0]
        assert isinstance(example, dict)
        assert example["request_id"] == "oadr-0002-0000-0000-000000000002"
        response = OperationAwareDecisionResponse.model_validate(example)
        dumped = response.model_dump(mode="json", exclude_none=True)
        assert dumped["request_id"] == "oadr-0002-0000-0000-000000000002"
        assert dumped["outcome"] == "allow"
        assert dumped["failure_reason"] is None
        assert dumped["trace_id"] == "trace-0001-0000-0000-000000000001"
        assert dumped["evaluation_trace"]["trace_id"] == "trace-0001-0000-0000-000000000001"

    def test_failed_example_retains_required_nulls(self) -> None:
        example = _VALID_EXAMPLES[3]
        assert isinstance(example, dict)
        assert example["evaluation_status"] == "failed"
        response = OperationAwareDecisionResponse.model_validate(example)
        assert response.outcome is None
        assert response.failure_reason == OperationAwareFailureReason.UNSUPPORTED_SCHEMA_VERSION
        dumped = response.model_dump(mode="json", exclude_none=True)
        assert "outcome" in dumped
        assert dumped["outcome"] is None

    def test_minimal_valid_example_only_required_keys(self) -> None:
        example = _VALID_EXAMPLES[4]
        assert isinstance(example, dict)
        assert set(example) == {"request_id", "evaluation_status", "outcome", "failure_reason"}
        response = OperationAwareDecisionResponse.model_validate(example)
        assert response.evaluation_status is OperationAwareEvaluationStatus.COMPLETED


# ══════════════════════════════════════════════════════════════════════════
# Model configuration and exact field inventory
# ══════════════════════════════════════════════════════════════════════════


class TestModelConfiguration:
    def test_model_is_frozen(self) -> None:
        assert OperationAwareDecisionResponse.model_config.get("frozen") is True

    def test_model_forbids_extra_fields(self) -> None:
        assert OperationAwareDecisionResponse.model_config.get("extra") == "forbid"

    def test_only_the_eleven_published_fields_exist(self) -> None:
        assert set(OperationAwareDecisionResponse.model_fields) == {
            "request_id",
            "correlation_id",
            "evaluation_status",
            "outcome",
            "failure_reason",
            "bundle_id",
            "bundle_version",
            "trace_id",
            "evaluation_trace",
            "reason_code",
            "explanation",
        }

    def test_unknown_top_level_field_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwareDecisionResponse(**_MINIMAL_COMPLETED_ALLOW_KWARGS, confidence=0.97)  # type: ignore[arg-type]


# ══════════════════════════════════════════════════════════════════════════
# Required-key behavior
# ══════════════════════════════════════════════════════════════════════════


class TestRequiredFields:
    @pytest.mark.parametrize(
        "field_name", ["request_id", "evaluation_status", "outcome", "failure_reason"]
    )
    def test_required_fields_are_required(self, field_name: str) -> None:
        assert OperationAwareDecisionResponse.model_fields[field_name].is_required()

    @pytest.mark.parametrize(
        "field_name",
        [
            "correlation_id",
            "bundle_id",
            "bundle_version",
            "trace_id",
            "evaluation_trace",
            "reason_code",
            "explanation",
        ],
    )
    def test_optional_fields_are_not_required(self, field_name: str) -> None:
        assert not OperationAwareDecisionResponse.model_fields[field_name].is_required()

    @pytest.mark.parametrize(
        "field_name", ["request_id", "evaluation_status", "outcome", "failure_reason"]
    )
    def test_missing_each_required_key_is_rejected(self, field_name: str) -> None:
        kwargs = dict(_MINIMAL_COMPLETED_ALLOW_KWARGS)
        del kwargs[field_name]
        with pytest.raises(ValidationError):
            OperationAwareDecisionResponse(**kwargs)  # type: ignore[arg-type]

    def test_explicit_null_rejected_for_request_id_and_evaluation_status(self) -> None:
        for field_name in ("request_id", "evaluation_status"):
            kwargs = dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, **{field_name: None})
            with pytest.raises(ValidationError):
                OperationAwareDecisionResponse(**kwargs)  # type: ignore[arg-type]

    def test_explicit_null_accepted_for_required_nullable_fields_in_valid_state(self) -> None:
        response = OperationAwareDecisionResponse(**_MINIMAL_FAILED_KWARGS)
        assert response.outcome is None

    def test_optional_fields_default_to_none_when_omitted(self) -> None:
        response = OperationAwareDecisionResponse(**_MINIMAL_COMPLETED_ALLOW_KWARGS)
        assert response.correlation_id is None
        assert response.bundle_id is None
        assert response.bundle_version is None
        assert response.trace_id is None
        assert response.evaluation_trace is None
        assert response.reason_code is None
        assert response.explanation is None

    def test_no_request_id_auto_generation(self) -> None:
        # request_id has no default factory; omitting it is rejected, never
        # silently filled in (see test_missing_each_required_key_is_rejected
        # above for the mechanical proof; this documents the identifier
        # itself remains caller-supplied).
        assert not OperationAwareDecisionResponse.model_fields["request_id"].default_factory

    def test_request_id_is_caller_supplied_not_derived(self) -> None:
        response = OperationAwareDecisionResponse(
            **dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, request_id="caller-supplied-id")
        )
        assert response.request_id == "caller-supplied-id"

    def test_empty_request_id_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwareDecisionResponse(**dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, request_id=""))

    def test_whitespace_only_request_id_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwareDecisionResponse(
                **dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, request_id="   ")
            )


# ══════════════════════════════════════════════════════════════════════════
# Evaluation-state matrix — the invariant this response's own fields enforce
# ══════════════════════════════════════════════════════════════════════════


class TestEvaluationStateMatrix:
    # ── Valid combinations ───────────────────────────────────────────────

    def test_completed_allow_valid(self) -> None:
        OperationAwareDecisionResponse(**dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, outcome="allow"))

    def test_completed_deny_valid(self) -> None:
        OperationAwareDecisionResponse(**dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, outcome="deny"))

    def test_completed_not_applicable_valid(self) -> None:
        OperationAwareDecisionResponse(
            **dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, outcome="not_applicable")
        )

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
        response = OperationAwareDecisionResponse(
            **dict(_MINIMAL_FAILED_KWARGS, failure_reason=reason)
        )
        assert response.outcome is None
        assert response.failure_reason == OperationAwareFailureReason(reason)

    # ── Invalid combinations ─────────────────────────────────────────────

    def test_completed_null_outcome_invalid(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwareDecisionResponse(**dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, outcome=None))

    def test_completed_non_null_failure_reason_invalid(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwareDecisionResponse(
                **dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, failure_reason="internal_evaluation_error")
            )

    def test_failed_allow_invalid(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwareDecisionResponse(**dict(_MINIMAL_FAILED_KWARGS, outcome="allow"))

    def test_failed_deny_invalid(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwareDecisionResponse(**dict(_MINIMAL_FAILED_KWARGS, outcome="deny"))

    def test_failed_not_applicable_invalid(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwareDecisionResponse(**dict(_MINIMAL_FAILED_KWARGS, outcome="not_applicable"))

    def test_failed_null_failure_reason_invalid(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwareDecisionResponse(**dict(_MINIMAL_FAILED_KWARGS, failure_reason=None))

    def test_evaluation_never_normalizes_failed_null_into_completed_deny(self) -> None:
        # Explicit regression for the brief's central invariant: a failed
        # evaluation is never silently reinterpreted as a completed deny.
        response = OperationAwareDecisionResponse(**_MINIMAL_FAILED_KWARGS)
        assert response.evaluation_status is OperationAwareEvaluationStatus.FAILED
        assert response.outcome is None
        assert response.outcome != OperationAwareDecisionOutcome.DENY


# ══════════════════════════════════════════════════════════════════════════
# Field behavior — bundle identity, reason_code, explanation, trace_id
# ══════════════════════════════════════════════════════════════════════════


class TestFieldBehavior:
    def test_valid_bundle_id_and_version_accepted(self) -> None:
        response = OperationAwareDecisionResponse(
            **dict(
                _MINIMAL_COMPLETED_ALLOW_KWARGS,
                bundle_id="baseline-read-only-telemetry",
                bundle_version="1.0.0",
            )
        )
        assert response.bundle_id == "baseline-read-only-telemetry"
        assert response.bundle_version == "1.0.0"

    def test_empty_bundle_id_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwareDecisionResponse(**dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, bundle_id=""))

    @pytest.mark.parametrize("version", ["v1", "1.0", "1.0.0.0", "1.0.0-rc1", "latest"])
    def test_invalid_bundle_version_rejected(self, version: str) -> None:
        with pytest.raises(ValidationError):
            OperationAwareDecisionResponse(
                **dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, bundle_version=version)
            )

    def test_reason_code_validated_through_governed_reason_code_type(self) -> None:
        response = OperationAwareDecisionResponse(
            **dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, reason_code="allow_rule_matched")
        )
        assert response.reason_code == "allow_rule_matched"

    def test_malformed_reason_code_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwareDecisionResponse(
                **dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, reason_code="ALLOW_RULE_MATCHED")
            )

    def test_valid_explanation_accepted(self) -> None:
        response = OperationAwareDecisionResponse(
            **dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, explanation="Operator role matched.")
        )
        assert response.explanation == "Operator role matched."

    def test_empty_explanation_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwareDecisionResponse(**dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, explanation=""))

    def test_valid_trace_id_accepted(self) -> None:
        response = OperationAwareDecisionResponse(
            **dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, trace_id="trace-0001")
        )
        assert response.trace_id == "trace-0001"

    def test_empty_trace_id_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwareDecisionResponse(**dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, trace_id=""))

    def test_trace_id_only_no_embedded_trace_valid(self) -> None:
        response = OperationAwareDecisionResponse(
            **dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, trace_id="trace-0001")
        )
        assert response.trace_id == "trace-0001"
        assert response.evaluation_trace is None

    def test_neither_trace_id_nor_embedded_trace_valid(self) -> None:
        # This PR does not invent an "at least one of trace_id/
        # evaluation_trace required" rule — the vendored contract does not
        # publish one (both are independently optional).
        response = OperationAwareDecisionResponse(**_MINIMAL_COMPLETED_ALLOW_KWARGS)
        assert response.trace_id is None
        assert response.evaluation_trace is None

    def test_this_pr_does_not_generate_a_trace_id(self) -> None:
        assert not OperationAwareDecisionResponse.model_fields["trace_id"].default_factory


# ══════════════════════════════════════════════════════════════════════════
# Embedded evaluation_trace — type and the narrow agreement subset enforced
# ══════════════════════════════════════════════════════════════════════════


class TestEmbeddedTrace:
    def test_embedded_trace_must_be_a_valid_evaluation_trace(self) -> None:
        response = OperationAwareDecisionResponse(
            **dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, evaluation_trace=_MINIMAL_TRACE_KWARGS)
        )
        assert type(response.evaluation_trace) is EvaluationTrace

    def test_malformed_embedded_trace_rejected_through_pr25_model(self) -> None:
        malformed = dict(_MINIMAL_TRACE_KWARGS)
        del malformed["trace_id"]
        with pytest.raises(ValidationError):
            OperationAwareDecisionResponse(
                **dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, evaluation_trace=malformed)
            )

    def test_completed_response_with_completed_allow_trace(self) -> None:
        response = OperationAwareDecisionResponse(
            **dict(
                _MINIMAL_COMPLETED_ALLOW_KWARGS,
                evaluation_trace=_MINIMAL_TRACE_KWARGS,
            )
        )
        assert response.evaluation_status is OperationAwareEvaluationStatus.COMPLETED
        assert response.evaluation_trace is not None
        assert response.evaluation_trace.evaluation_status.value == "completed"
        assert response.evaluation_trace.outcome.value == "allow"

    def test_failed_response_with_failed_trace_carrying_policy_validation_failure(self) -> None:
        failed_trace_kwargs: dict[str, object] = {
            "trace_id": "trace-test-failed",
            "request_id": "oadr-test-failed",
            "evaluation_status": "failed",
            "outcome": None,
            "bundle_applicability": None,
            "failure_reason": "policy_validation_failure",
            "rule_evidence": [],
        }
        response = OperationAwareDecisionResponse(
            **dict(
                _MINIMAL_FAILED_KWARGS,
                failure_reason="policy_validation_failure",
                evaluation_trace=failed_trace_kwargs,
            )
        )
        assert response.evaluation_status is OperationAwareEvaluationStatus.FAILED
        assert response.outcome is None
        assert response.evaluation_trace is not None
        assert response.evaluation_trace.outcome is None
        assert response.evaluation_trace.bundle_applicability is None
        assert response.evaluation_trace.failure_reason.value == "policy_validation_failure"

    # ── Narrow agreement subset (see response.py's module docstring) ─────

    def test_request_id_mismatch_rejected(self) -> None:
        mismatched_trace = dict(_MINIMAL_TRACE_KWARGS, request_id="different-request-id")
        with pytest.raises(ValidationError):
            OperationAwareDecisionResponse(
                **dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, evaluation_trace=mismatched_trace)
            )

    def test_request_id_agreement_accepted(self) -> None:
        response = OperationAwareDecisionResponse(
            **dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, evaluation_trace=_MINIMAL_TRACE_KWARGS)
        )
        assert response.evaluation_trace is not None
        assert response.evaluation_trace.request_id == response.request_id

    def test_correlation_id_mismatch_rejected_when_both_present(self) -> None:
        mismatched_trace = dict(_MINIMAL_TRACE_KWARGS, correlation_id="corr-different")
        with pytest.raises(ValidationError):
            OperationAwareDecisionResponse(
                **dict(
                    _MINIMAL_COMPLETED_ALLOW_KWARGS,
                    correlation_id="corr-original",
                    evaluation_trace=mismatched_trace,
                )
            )

    def test_correlation_id_not_checked_when_only_one_side_present(self) -> None:
        # Neither side supplies correlation_id here except the trace; the
        # contract's own prose ties this agreement to "when both are
        # present" — this is not a mismatch.
        trace_with_correlation = dict(_MINIMAL_TRACE_KWARGS, correlation_id="corr-only-on-trace")
        response = OperationAwareDecisionResponse(
            **dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, evaluation_trace=trace_with_correlation)
        )
        assert response.correlation_id is None

    def test_failure_reason_mismatch_rejected(self) -> None:
        mismatched_trace = dict(
            _MINIMAL_TRACE_KWARGS,
            evaluation_status="failed",
            outcome=None,
            bundle_applicability=None,
            failure_reason="unsupported_schema_version",
        )
        with pytest.raises(ValidationError):
            OperationAwareDecisionResponse(
                **dict(
                    _MINIMAL_FAILED_KWARGS,
                    failure_reason="internal_evaluation_error",
                    evaluation_trace=mismatched_trace,
                )
            )

    def test_reason_code_mismatch_rejected_when_both_non_null(self) -> None:
        mismatched_trace = dict(_MINIMAL_TRACE_KWARGS, reason_code="no_applicable_bundle")
        with pytest.raises(ValidationError):
            OperationAwareDecisionResponse(
                **dict(
                    _MINIMAL_COMPLETED_ALLOW_KWARGS,
                    reason_code="allow_rule_matched",
                    evaluation_trace=mismatched_trace,
                )
            )

    def test_reason_code_not_checked_when_only_one_side_present(self) -> None:
        trace_with_reason_code = dict(_MINIMAL_TRACE_KWARGS, reason_code="allow_rule_matched")
        response = OperationAwareDecisionResponse(
            **dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, evaluation_trace=trace_with_reason_code)
        )
        assert response.reason_code is None

    def test_this_pr_does_not_enforce_trace_id_vs_embedded_trace_trace_id_agreement(self) -> None:
        # Deliberately deferred to PR 32 — see response.py's module
        # docstring, "Response/trace agreement." Not exercised by any
        # vendored invalid example; this test documents the deferral
        # positively (construction succeeds) rather than leaving it
        # unstated.
        response = OperationAwareDecisionResponse(
            **dict(
                _MINIMAL_COMPLETED_ALLOW_KWARGS,
                trace_id="top-level-trace-id",
                evaluation_trace=dict(
                    _MINIMAL_TRACE_KWARGS, trace_id="different-embedded-trace-id"
                ),
            )
        )
        assert response.trace_id == "top-level-trace-id"
        assert response.evaluation_trace is not None
        assert response.evaluation_trace.trace_id == "different-embedded-trace-id"


# ══════════════════════════════════════════════════════════════════════════
# Boundedness and security
# ══════════════════════════════════════════════════════════════════════════


class TestBoundednessAndSecurity:
    @pytest.mark.parametrize(
        "field_name",
        [
            "enforcement_result",
            "http_status",
            "response_status",
            "route",
            "full_request",
            "request_snapshot",
            "full_policy",
            "policy_document",
            "raw_claims",
            "full_claim_set",
            "raw_payload",
            "raw_protocol_payload",
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
            "event_id",
            "event_type",
        ],
    )
    def test_raw_or_sensitive_or_gateway_field_rejected_as_unknown(self, field_name: str) -> None:
        with pytest.raises(ValidationError):
            OperationAwareDecisionResponse(**_MINIMAL_COMPLETED_ALLOW_KWARGS, **{field_name: "x"})  # type: ignore[arg-type]


# ══════════════════════════════════════════════════════════════════════════
# Frozen-model behavior
# ══════════════════════════════════════════════════════════════════════════


class TestImmutability:
    def test_top_level_field_reassignment_rejected(self) -> None:
        response = OperationAwareDecisionResponse(**_MINIMAL_COMPLETED_ALLOW_KWARGS)
        with pytest.raises(ValidationError):
            response.outcome = OperationAwareDecisionOutcome.DENY  # type: ignore[misc]


# ══════════════════════════════════════════════════════════════════════════
# Serialization
# ══════════════════════════════════════════════════════════════════════════


class TestSerialization:
    def test_plain_model_dump_names_every_published_field(self) -> None:
        response = OperationAwareDecisionResponse(**_MINIMAL_COMPLETED_ALLOW_KWARGS)
        dumped = response.model_dump(mode="json")
        assert set(dumped) == {
            "request_id",
            "correlation_id",
            "evaluation_status",
            "outcome",
            "failure_reason",
            "bundle_id",
            "bundle_version",
            "trace_id",
            "evaluation_trace",
            "reason_code",
            "explanation",
        }

    def test_direct_model_dump_retains_required_nullable_keys(self) -> None:
        response = OperationAwareDecisionResponse(**_MINIMAL_FAILED_KWARGS)
        dumped = response.model_dump(mode="json", exclude_none=True)
        assert "outcome" in dumped
        assert dumped["outcome"] is None
        assert dumped["failure_reason"] == "internal_evaluation_error"
        assert "correlation_id" not in dumped
        assert "bundle_id" not in dumped
        assert "trace_id" not in dumped
        assert "evaluation_trace" not in dumped

    def test_direct_model_dump_json_retains_required_nullable_keys(self) -> None:
        response = OperationAwareDecisionResponse(**_MINIMAL_FAILED_KWARGS)
        raw = response.model_dump_json(exclude_none=True)
        parsed = json.loads(raw)
        assert "outcome" in parsed
        assert parsed["outcome"] is None
        assert "correlation_id" not in parsed

    def test_direct_serialization_with_exclude_none_omits_absent_optional_fields(self) -> None:
        response = OperationAwareDecisionResponse(**_MINIMAL_COMPLETED_ALLOW_KWARGS)
        dumped = response.model_dump(mode="json", exclude_none=True)
        # request_id, evaluation_status, outcome, and failure_reason are all
        # required keys on this response (outcome/failure_reason are
        # required-nullable — see _REQUIRED_NULLABLE_FIELDS in response.py),
        # so failure_reason: None is restored even though exclude_none=True
        # would otherwise drop it; every other optional field is genuinely
        # absent here and correctly omitted.
        assert dumped == {
            "request_id": "oadr-test-completed-allow",
            "evaluation_status": "completed",
            "outcome": "allow",
            "failure_reason": None,
        }

    def test_completed_response_retains_required_nullable_failure_reason_under_exclude_none(
        self,
    ) -> None:
        # failure_reason is a required key (like outcome) — see the module
        # docstring's "Required-nullable serialization" — so it is restored
        # as explicit null under exclude_none=True even though its value is
        # None, unlike a genuinely optional field (e.g. correlation_id).
        response = OperationAwareDecisionResponse(**_MINIMAL_COMPLETED_ALLOW_KWARGS)
        dumped = response.model_dump(mode="json", exclude_none=True)
        assert "failure_reason" in dumped
        assert dumped["failure_reason"] is None
        assert "correlation_id" not in dumped


# ══════════════════════════════════════════════════════════════════════════
# Nested serialization — response embedding EvaluationTrace, and response
# nested inside a further wrapper model
# ══════════════════════════════════════════════════════════════════════════


class _ResponseWrapper(BaseModel):
    """Local, test-only wrapper standing in for a future parent model (e.g.
    a gateway envelope) that embeds `OperationAwareDecisionResponse`."""

    response: OperationAwareDecisionResponse


def _failed_response_with_embedded_trace_for_serialization_regressions() -> (
    OperationAwareDecisionResponse
):
    failed_trace_kwargs: dict[str, object] = {
        "trace_id": "trace-serialization-regression",
        "request_id": "oadr-serialization-regression",
        "evaluation_status": "failed",
        "outcome": None,
        "bundle_applicability": None,
        "failure_reason": "internal_evaluation_error",
        "rule_evidence": [],
    }
    return OperationAwareDecisionResponse(
        request_id="oadr-serialization-regression",
        evaluation_status="failed",
        outcome=None,
        failure_reason="internal_evaluation_error",
        evaluation_trace=failed_trace_kwargs,
    )


class TestNestedSerialization:
    def test_embedded_trace_required_nullable_keys_survive_response_dump(self) -> None:
        response = _failed_response_with_embedded_trace_for_serialization_regressions()
        dumped = response.model_dump(mode="json", exclude_none=True)
        nested = dumped["evaluation_trace"]
        assert "outcome" in nested
        assert nested["outcome"] is None
        assert "bundle_applicability" in nested
        assert nested["bundle_applicability"] is None

    def test_embedded_trace_required_nullable_keys_survive_response_dump_json(self) -> None:
        response = _failed_response_with_embedded_trace_for_serialization_regressions()
        raw = response.model_dump_json(exclude_none=True)
        parsed = json.loads(raw)
        nested = parsed["evaluation_trace"]
        assert nested["outcome"] is None
        assert nested["bundle_applicability"] is None

    def test_wrapper_model_dump_retains_required_nullable_keys_at_both_levels(self) -> None:
        response = _failed_response_with_embedded_trace_for_serialization_regressions()
        wrapper = _ResponseWrapper(response=response)
        dumped = wrapper.model_dump(mode="json", exclude_none=True)
        nested_response = dumped["response"]
        assert "outcome" in nested_response
        assert nested_response["outcome"] is None
        nested_trace = nested_response["evaluation_trace"]
        assert nested_trace["outcome"] is None
        assert nested_trace["bundle_applicability"] is None

    def test_wrapper_model_dump_json_retains_required_nullable_keys_at_both_levels(self) -> None:
        response = _failed_response_with_embedded_trace_for_serialization_regressions()
        wrapper = _ResponseWrapper(response=response)
        raw = wrapper.model_dump_json(exclude_none=True)
        parsed = json.loads(raw)
        nested_response = parsed["response"]
        assert nested_response["outcome"] is None
        nested_trace = nested_response["evaluation_trace"]
        assert nested_trace["outcome"] is None
        assert nested_trace["bundle_applicability"] is None

    def test_wrapper_round_trip_preserves_full_structure(self) -> None:
        response = _failed_response_with_embedded_trace_for_serialization_regressions()
        wrapper = _ResponseWrapper(response=response)
        dumped = wrapper.model_dump(mode="json", exclude_none=True)
        restored = _ResponseWrapper.model_validate(dumped)
        assert restored == wrapper


# ══════════════════════════════════════════════════════════════════════════
# Explicit include/exclude take precedence over required-nullable
# restoration — mirrors EvaluationTrace's own regression coverage for the
# same defect class (a model_dump override re-adding an explicitly excluded
# key, or re-adding unselected keys under include).
# ══════════════════════════════════════════════════════════════════════════


class TestIncludeExcludeTakePrecedence:
    def test_include_selects_only_named_fields(self) -> None:
        response = OperationAwareDecisionResponse(**_MINIMAL_FAILED_KWARGS)
        dumped = response.model_dump(
            mode="json", include={"request_id", "outcome"}, exclude_none=True
        )
        assert dumped == {"request_id": "oadr-test-failed", "outcome": None}

    def test_include_does_not_reintroduce_unselected_required_nullable_fields(self) -> None:
        response = OperationAwareDecisionResponse(**_MINIMAL_FAILED_KWARGS)
        dumped = response.model_dump(mode="json", include={"request_id"}, exclude_none=True)
        assert dumped == {"request_id": "oadr-test-failed"}
        assert "outcome" not in dumped
        assert "failure_reason" not in dumped

    def test_exclude_is_not_overridden_by_required_nullable_restoration(self) -> None:
        response = OperationAwareDecisionResponse(**_MINIMAL_FAILED_KWARGS)
        dumped = response.model_dump(mode="json", exclude={"outcome"}, exclude_none=True)
        assert "outcome" not in dumped
        # failure_reason was not excluded, so it is still present (non-null
        # here, so it would be present regardless of the restoration logic).
        assert dumped["failure_reason"] == "internal_evaluation_error"


# ══════════════════════════════════════════════════════════════════════════
# Shared vocabulary parity — OperationAwareEvaluationStatus/
# OperationAwareDecisionOutcome vs. the audit-owned trace vocabularies
# ══════════════════════════════════════════════════════════════════════════


class TestSharedVocabularyParity:
    def test_evaluation_status_member_names_and_values_match_trace_vocabulary(self) -> None:
        from basis_core.audit.operation_aware.evaluation_trace import EvaluationStatus

        assert {member.name: member.value for member in OperationAwareEvaluationStatus} == {
            member.name: member.value for member in EvaluationStatus
        }

    def test_decision_outcome_member_names_and_values_match_trace_vocabulary(self) -> None:
        from basis_core.audit.operation_aware.evaluation_trace import TraceOutcome

        assert {member.name: member.value for member in OperationAwareDecisionOutcome} == {
            member.name: member.value for member in TraceOutcome
        }

    def test_evaluation_status_is_decisions_owned_not_audit_owned(self) -> None:
        assert OperationAwareEvaluationStatus.__module__ == "basis_core.decisions.operation_aware"

    def test_decision_outcome_is_decisions_owned_not_audit_owned(self) -> None:
        assert OperationAwareDecisionOutcome.__module__ == "basis_core.decisions.operation_aware"


# ══════════════════════════════════════════════════════════════════════════
# v0.1 compatibility — OperationAwareDecisionResponse is separate from
# DecisionResponse
# ══════════════════════════════════════════════════════════════════════════


class TestV01Compatibility:
    """Mandatory regression: the existing v0.1.0
    `basis_core.decisions.models.DecisionResponse` type (and its
    `DecisionOutcome`/`FailureReason` vocabularies) is untouched by anything
    added in this PR. `OperationAwareDecisionResponse` is a distinct symbol,
    never aliased to `DecisionResponse`, never a subclass of it, and never
    exported from the same module."""

    def test_decision_response_import_still_resolves(self) -> None:
        from basis_core.decisions.models import DecisionResponse

        assert DecisionResponse.__module__ == "basis_core.decisions.models"

    def test_decision_response_fields_unchanged(self) -> None:
        from basis_core.decisions.models import DecisionResponse

        assert set(DecisionResponse.model_fields) == {
            "request_id",
            "outcome",
            "reason",
            "evaluated_by",
            "policy_version",
            "failure_reason",
            "timestamp",
        }

    def test_decision_response_still_constructs_and_serializes(self) -> None:
        from basis_core.decisions.models import DecisionOutcome, DecisionResponse

        response = DecisionResponse(
            request_id="req-1",
            outcome=DecisionOutcome.ALLOW,
            reason="matched role policy",
            evaluated_by="RolePolicyRule",
        )
        dumped = response.model_dump(mode="json")
        assert dumped["outcome"] == "allow"
        assert dumped["request_id"] == "req-1"

    def test_decision_outcome_and_failure_reason_unchanged(self) -> None:
        from basis_core.decisions.models import DecisionOutcome, FailureReason

        assert {member.value for member in DecisionOutcome} == {"allow", "deny", "not_applicable"}
        assert {member.value for member in FailureReason} == {
            "malformed_request",
            "policy_error",
            "audit_error",
            "internal_error",
        }

    def test_operation_aware_decision_response_is_not_decision_response(self) -> None:
        from basis_core.decisions.models import DecisionResponse

        assert OperationAwareDecisionResponse is not DecisionResponse
        assert not issubclass(OperationAwareDecisionResponse, DecisionResponse)
        assert not issubclass(DecisionResponse, OperationAwareDecisionResponse)

    def test_constructing_operation_aware_response_has_no_shared_mutable_state(self) -> None:
        from basis_core.decisions.models import DecisionOutcome, DecisionResponse

        OperationAwareDecisionResponse(**_MINIMAL_COMPLETED_ALLOW_KWARGS)
        response = DecisionResponse(
            request_id="req-1",
            outcome=DecisionOutcome.ALLOW,
            reason="matched role policy",
            evaluated_by="RolePolicyRule",
        )
        assert response.outcome is DecisionOutcome.ALLOW


# ══════════════════════════════════════════════════════════════════════════
# Public API boundary — OperationAwareDecisionResponse is not prematurely
# public
# ══════════════════════════════════════════════════════════════════════════


class TestPublicAPIBoundary:
    def test_not_exported_from_basis_core_evaluation(self) -> None:
        import basis_core.evaluation as evaluation_package

        assert not hasattr(evaluation_package, "OperationAwareDecisionResponse")

    def test_not_exported_from_operation_aware_package_init(self) -> None:
        import basis_core.evaluation.operation_aware as oa_evaluation_package

        assert not hasattr(oa_evaluation_package, "OperationAwareDecisionResponse")
