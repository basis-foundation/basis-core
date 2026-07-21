"""
tests/operation_aware/test_evaluation_trace.py — tests for
`basis_core.audit.operation_aware.evaluation_trace.EvaluationTrace`
(Milestone 8, PR 25 of
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`:
"EvaluationTrace model").

Covers `EvaluationTrace`/`EvaluationStatus`/`TraceOutcome`/
`TraceBundleApplicability`/`TraceFailureReason` construction, validation,
the published required-key/nullable-key distinctions, every published
cross-field invariant, deterministic `rule_evidence` ordering preservation,
immutability, boundedness, and serialization — cross-checked against every
vendored `basis-schemas` v0.2.0 `evaluation-trace` contract example (five
valid, sixteen invalid) via the existing test-only loader
(`tests/helpers/operation_aware_contracts.py`).

This file tests bounded trace *shape* only: construction, validation,
immutability, and schema alignment. It does not test, and must never test,
trace assembly, conversion from any internal evaluator result, the future
`OperationAwareDecisionResponse`, or `AuditEvidence` — none of that exists in
this module or this PR (PR 26 onward). `TestV01Compatibility` is the
mandatory, mechanically-checked proof that `basis_core.audit.trace.
DecisionTrace`/`RuleEvaluation` (the existing v0.1.0 types) are unaffected by
anything added here.
"""

from __future__ import annotations

import json

import pytest
from pydantic import BaseModel, ValidationError

from basis_core.audit.operation_aware.evaluation_trace import (
    EvaluationStatus,
    EvaluationTrace,
    TraceBundleApplicability,
    TraceFailureReason,
    TraceOutcome,
)
from basis_core.audit.operation_aware.trace_rule_evidence import TraceRuleEvidence
from tests.helpers.operation_aware_contracts import (
    load_contract,
    require_mapping_field,
    require_sequence_field,
)

# ══════════════════════════════════════════════════════════════════════════
# Fixture loading
# ══════════════════════════════════════════════════════════════════════════


def _evaluation_trace_examples() -> tuple[list[object], list[object]]:
    document = load_contract("evaluation-trace")
    section = require_mapping_field(document, "evaluation_trace", context="evaluation-trace")
    examples = require_mapping_field(
        section, "examples", context="evaluation-trace.evaluation_trace"
    )
    valid = require_sequence_field(examples, "valid", context="evaluation-trace.examples")
    invalid = require_sequence_field(examples, "invalid", context="evaluation-trace.examples")
    return valid, invalid


_VALID_EXAMPLES, _INVALID_EXAMPLES = _evaluation_trace_examples()


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
        trace_id = example.get("trace_id")
        if isinstance(trace_id, str) and trace_id:
            return trace_id
    return f"example-{index}"


# Minimal structurally valid records reused across tests that need one but
# are not themselves testing the field under test.
_MINIMAL_COMPLETED_ALLOW_KWARGS: dict[str, object] = {
    "trace_id": "trace-test-completed-allow",
    "request_id": "oadr-test-completed-allow",
    "evaluation_status": "completed",
    "outcome": "allow",
    "bundle_applicability": "applicable",
    "rule_evidence": [],
}

_MINIMAL_FAILED_KWARGS: dict[str, object] = {
    "trace_id": "trace-test-failed",
    "request_id": "oadr-test-failed",
    "evaluation_status": "failed",
    "outcome": None,
    "bundle_applicability": None,
    "failure_reason": "internal_evaluation_error",
    "rule_evidence": [],
}

_MINIMAL_RULE_EVIDENCE_KWARGS: dict[str, object] = {
    "rule_id": "rule-1",
    "effect": "allow",
    "rule_result": "matched",
}


# ══════════════════════════════════════════════════════════════════════════
# Fixture conformance — every vendored valid/invalid example
# ══════════════════════════════════════════════════════════════════════════


class TestFixtureConformance:
    def test_five_valid_examples_are_vendored(self) -> None:
        # A supplementary count check — the parametrized tests below are the
        # primary completeness mechanism; this only guards against a
        # coincidental simultaneous add+remove in the vendored fixture.
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
        trace = EvaluationTrace.model_validate(example)
        assert type(trace) is EvaluationTrace
        assert all(type(entry) is TraceRuleEvidence for entry in trace.rule_evidence)

    @pytest.mark.parametrize(
        "entry",
        _INVALID_EXAMPLES,
        ids=[_invalid_example_reason(ex, i) for i, ex in enumerate(_INVALID_EXAMPLES)],
    )
    def test_invalid_example_is_rejected(self, entry: object) -> None:
        value = _invalid_example_value(entry)
        with pytest.raises(ValidationError):
            EvaluationTrace.model_validate(value)

    @pytest.mark.parametrize(
        "example",
        _VALID_EXAMPLES,
        ids=[_valid_example_id(ex, i) for i, ex in enumerate(_VALID_EXAMPLES)],
    )
    def test_all_vendored_valid_examples_round_trip(self, example: object) -> None:
        assert isinstance(example, dict)
        trace = EvaluationTrace.model_validate(example)
        dumped = trace.model_dump(mode="json", exclude_none=True)
        restored = EvaluationTrace.model_validate(dumped)
        assert restored == trace

    def test_allow_example_serializes_expected_shape(self) -> None:
        example = _VALID_EXAMPLES[0]
        assert isinstance(example, dict)
        assert example["trace_id"] == "trace-0001-0000-0000-000000000001"
        trace = EvaluationTrace.model_validate(example)
        dumped = trace.model_dump(mode="json", exclude_none=True)
        assert dumped == {
            "trace_id": "trace-0001-0000-0000-000000000001",
            "request_id": "oadr-0002-0000-0000-000000000002",
            "evaluation_status": "completed",
            "outcome": "allow",
            "bundle_applicability": "applicable",
            "bundle_id": "baseline-read-only-telemetry",
            "bundle_version": "1.0.0",
            "rule_evidence": [
                {
                    "rule_id": "rule-operator-read-ahu-telemetry",
                    "effect": "allow",
                    "rule_result": "matched",
                    "reason_code": "allow_rule_matched",
                }
            ],
            "reason_code": "allow_rule_matched",
            "explanation": "Operator role matched an allow rule for read:ahu.",
        }

    def test_failed_before_applicability_example_serializes_required_nulls(self) -> None:
        # example 4: a failure detected before bundle applicability could be
        # established — outcome and bundle_applicability are both null, and
        # both keys MUST still be present in the dumped shape (this model's
        # serialization override; see the module docstring).
        example = _VALID_EXAMPLES[3]
        assert isinstance(example, dict)
        assert example["trace_id"] == "trace-0004-0000-0000-000000000004"
        trace = EvaluationTrace.model_validate(example)
        dumped = trace.model_dump(mode="json", exclude_none=True)
        assert dumped == {
            "trace_id": "trace-0004-0000-0000-000000000004",
            "request_id": "oadr-1099-0000-0000-000000000099",
            "evaluation_status": "failed",
            "outcome": None,
            "bundle_applicability": None,
            "failure_reason": "unsupported_schema_version",
            "rule_evidence": [],
            "explanation": ("The request declared a schema version this kernel does not support."),
        }

    def test_condition_evaluation_error_example_reconstructs_nested_evidence(self) -> None:
        # example 5: a failure inside an already-applicable bundle,
        # demonstrating bundle_applicability may remain "applicable" under a
        # failure, and that nested TraceRuleEvidence/TraceConditionEvidence
        # reconstruct correctly through EvaluationTrace.
        example = _VALID_EXAMPLES[4]
        assert isinstance(example, dict)
        assert example["trace_id"] == "trace-0005-0000-0000-000000000005"
        trace = EvaluationTrace.model_validate(example)
        assert trace.evaluation_status is EvaluationStatus.FAILED
        assert trace.outcome is None
        assert trace.bundle_applicability is TraceBundleApplicability.APPLICABLE
        assert trace.failure_reason is TraceFailureReason.CONDITION_EVALUATION_ERROR
        assert len(trace.rule_evidence) == 1
        (rule,) = trace.rule_evidence
        assert type(rule) is TraceRuleEvidence
        assert rule.condition_results is not None
        assert len(rule.condition_results) == 1


# ══════════════════════════════════════════════════════════════════════════
# Model configuration and exact field inventory
# ══════════════════════════════════════════════════════════════════════════


class TestModelConfiguration:
    def test_model_is_frozen(self) -> None:
        assert EvaluationTrace.model_config.get("frozen") is True

    def test_model_forbids_extra_fields(self) -> None:
        assert EvaluationTrace.model_config.get("extra") == "forbid"

    def test_only_the_twelve_published_fields_exist(self) -> None:
        assert set(EvaluationTrace.model_fields) == {
            "trace_id",
            "request_id",
            "correlation_id",
            "evaluation_status",
            "outcome",
            "bundle_applicability",
            "bundle_id",
            "bundle_version",
            "failure_reason",
            "rule_evidence",
            "reason_code",
            "explanation",
        }

    def test_unknown_top_level_field_rejected(self) -> None:
        with pytest.raises(ValidationError):
            EvaluationTrace(**_MINIMAL_COMPLETED_ALLOW_KWARGS, confidence=0.97)  # type: ignore[arg-type]


# ══════════════════════════════════════════════════════════════════════════
# Required-key behavior
# ══════════════════════════════════════════════════════════════════════════


class TestRequiredFields:
    @pytest.mark.parametrize(
        "field_name",
        [
            "trace_id",
            "request_id",
            "evaluation_status",
            "outcome",
            "bundle_applicability",
            "rule_evidence",
        ],
    )
    def test_required_fields_are_required(self, field_name: str) -> None:
        assert EvaluationTrace.model_fields[field_name].is_required()

    @pytest.mark.parametrize(
        "field_name",
        [
            "correlation_id",
            "bundle_id",
            "bundle_version",
            "failure_reason",
            "reason_code",
            "explanation",
        ],
    )
    def test_optional_fields_are_not_required(self, field_name: str) -> None:
        assert not EvaluationTrace.model_fields[field_name].is_required()

    @pytest.mark.parametrize(
        "field_name",
        [
            "trace_id",
            "request_id",
            "evaluation_status",
            "outcome",
            "bundle_applicability",
            "rule_evidence",
        ],
    )
    def test_missing_each_required_key_is_rejected(self, field_name: str) -> None:
        kwargs = dict(_MINIMAL_COMPLETED_ALLOW_KWARGS)
        del kwargs[field_name]
        with pytest.raises(ValidationError):
            EvaluationTrace(**kwargs)  # type: ignore[arg-type]

    def test_explicit_null_rejected_for_required_non_nullable_fields(self) -> None:
        for field_name in ("trace_id", "request_id", "evaluation_status", "rule_evidence"):
            kwargs = dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, **{field_name: None})
            with pytest.raises(ValidationError):
                EvaluationTrace(**kwargs)  # type: ignore[arg-type]

    def test_explicit_null_accepted_for_required_nullable_fields_in_valid_state(self) -> None:
        # outcome/bundle_applicability accept explicit null only in a
        # state-consistent combination (see TestEvaluationStateMatrix for
        # the full invariant); this proves null itself is not rejected
        # merely for being null.
        trace = EvaluationTrace(**_MINIMAL_FAILED_KWARGS)
        assert trace.outcome is None
        assert trace.bundle_applicability is None

    def test_optional_fields_default_to_none_when_omitted(self) -> None:
        trace = EvaluationTrace(**_MINIMAL_COMPLETED_ALLOW_KWARGS)
        assert trace.correlation_id is None
        assert trace.bundle_id is None
        assert trace.bundle_version is None
        assert trace.failure_reason is None
        assert trace.reason_code is None
        assert trace.explanation is None


# ══════════════════════════════════════════════════════════════════════════
# Trace identity
# ══════════════════════════════════════════════════════════════════════════


class TestTraceIdentity:
    def test_valid_trace_id_and_request_id_accepted(self) -> None:
        trace = EvaluationTrace(**_MINIMAL_COMPLETED_ALLOW_KWARGS)
        assert trace.trace_id == "trace-test-completed-allow"
        assert trace.request_id == "oadr-test-completed-allow"

    def test_empty_trace_id_rejected(self) -> None:
        with pytest.raises(ValidationError):
            EvaluationTrace(**dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, trace_id=""))

    def test_whitespace_only_trace_id_rejected(self) -> None:
        with pytest.raises(ValidationError):
            EvaluationTrace(**dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, trace_id="   "))

    def test_empty_request_id_rejected(self) -> None:
        with pytest.raises(ValidationError):
            EvaluationTrace(**dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, request_id=""))

    def test_whitespace_only_request_id_rejected(self) -> None:
        with pytest.raises(ValidationError):
            EvaluationTrace(**dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, request_id="   "))

    # No ID-generation test is needed beyond the missing-required-key tests
    # in TestRequiredFields: those already prove trace_id/request_id must be
    # explicitly supplied and are never silently filled in.


# ══════════════════════════════════════════════════════════════════════════
# evaluation_status (EvaluationStatus)
# ══════════════════════════════════════════════════════════════════════════


class TestEvaluationStatus:
    @pytest.mark.parametrize("status", ["completed", "failed"])
    def test_every_published_value_accepted(self, status: str) -> None:
        kwargs = (
            dict(_MINIMAL_COMPLETED_ALLOW_KWARGS)
            if status == "completed"
            else dict(_MINIMAL_FAILED_KWARGS)
        )
        kwargs["evaluation_status"] = status
        trace = EvaluationTrace(**kwargs)
        assert trace.evaluation_status == EvaluationStatus(status)

    @pytest.mark.parametrize("status", ["success", "error", "pending", "partial", ""])
    def test_unsupported_values_rejected(self, status: str) -> None:
        with pytest.raises(ValidationError):
            EvaluationTrace(**dict(_MINIMAL_FAILED_KWARGS, evaluation_status=status))

    @pytest.mark.parametrize("status", ["COMPLETED", "Completed", "FAILED", "Failed"])
    def test_case_variants_rejected(self, status: str) -> None:
        with pytest.raises(ValidationError):
            EvaluationTrace(**dict(_MINIMAL_FAILED_KWARGS, evaluation_status=status))

    def test_evaluation_status_serializes_exactly(self) -> None:
        trace = EvaluationTrace(**_MINIMAL_COMPLETED_ALLOW_KWARGS)
        dumped = trace.model_dump(mode="json")
        assert dumped["evaluation_status"] == "completed"
        assert isinstance(dumped["evaluation_status"], str)


# ══════════════════════════════════════════════════════════════════════════
# outcome (TraceOutcome)
# ══════════════════════════════════════════════════════════════════════════


class TestOutcome:
    @pytest.mark.parametrize("outcome", ["allow", "deny", "not_applicable"])
    def test_every_published_non_null_outcome_accepted_in_valid_state(self, outcome: str) -> None:
        applicability = "not_applicable" if outcome == "not_applicable" else "applicable"
        trace = EvaluationTrace(
            **dict(
                _MINIMAL_COMPLETED_ALLOW_KWARGS,
                outcome=outcome,
                bundle_applicability=applicability,
            )
        )
        assert trace.outcome == TraceOutcome(outcome)

    def test_null_outcome_accepted_in_valid_failed_state(self) -> None:
        trace = EvaluationTrace(**_MINIMAL_FAILED_KWARGS)
        assert trace.outcome is None

    @pytest.mark.parametrize("outcome", ["maybe", "permit", "reject", ""])
    def test_unsupported_outcomes_rejected(self, outcome: str) -> None:
        with pytest.raises(ValidationError):
            EvaluationTrace(**dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, outcome=outcome))

    @pytest.mark.parametrize("outcome", ["ALLOW", "Allow", "DENY", "NOT_APPLICABLE"])
    def test_case_variants_rejected(self, outcome: str) -> None:
        with pytest.raises(ValidationError):
            EvaluationTrace(**dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, outcome=outcome))

    def test_outcome_serializes_exactly(self) -> None:
        trace = EvaluationTrace(**_MINIMAL_COMPLETED_ALLOW_KWARGS)
        dumped = trace.model_dump(mode="json")
        assert dumped["outcome"] == "allow"
        assert isinstance(dumped["outcome"], str)

    def test_null_outcome_serializes_as_explicit_null(self) -> None:
        trace = EvaluationTrace(**_MINIMAL_FAILED_KWARGS)
        dumped = trace.model_dump(mode="json")
        assert dumped["outcome"] is None


# ══════════════════════════════════════════════════════════════════════════
# failure_reason (TraceFailureReason)
# ══════════════════════════════════════════════════════════════════════════


class TestFailureReason:
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
    def test_every_published_value_accepted_in_valid_failure_state(self, reason: str) -> None:
        trace = EvaluationTrace(**dict(_MINIMAL_FAILED_KWARGS, failure_reason=reason))
        assert trace.failure_reason == TraceFailureReason(reason)

    @pytest.mark.parametrize("reason", ["malformed_request", "policy_error", "unknown", ""])
    def test_unsupported_values_rejected(self, reason: str) -> None:
        with pytest.raises(ValidationError):
            EvaluationTrace(**dict(_MINIMAL_FAILED_KWARGS, failure_reason=reason))

    @pytest.mark.parametrize("reason", ["INVALID_REQUEST", "Internal_Evaluation_Error"])
    def test_case_variants_rejected(self, reason: str) -> None:
        with pytest.raises(ValidationError):
            EvaluationTrace(**dict(_MINIMAL_FAILED_KWARGS, failure_reason=reason))

    def test_missing_failure_reason_defaults_to_none(self) -> None:
        trace = EvaluationTrace(**_MINIMAL_COMPLETED_ALLOW_KWARGS)
        assert trace.failure_reason is None

    def test_explicit_null_failure_reason_accepted_when_completed(self) -> None:
        trace = EvaluationTrace(**dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, failure_reason=None))
        assert trace.failure_reason is None

    def test_non_null_failure_reason_rejected_when_completed(self) -> None:
        with pytest.raises(ValidationError):
            EvaluationTrace(
                **dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, failure_reason="internal_evaluation_error")
            )

    def test_null_failure_reason_rejected_when_failed(self) -> None:
        with pytest.raises(ValidationError):
            EvaluationTrace(**dict(_MINIMAL_FAILED_KWARGS, failure_reason=None))

    def test_missing_failure_reason_rejected_when_failed(self) -> None:
        kwargs = dict(_MINIMAL_FAILED_KWARGS)
        del kwargs["failure_reason"]
        with pytest.raises(ValidationError):
            EvaluationTrace(**kwargs)

    def test_failure_reason_serializes_exactly(self) -> None:
        trace = EvaluationTrace(**_MINIMAL_FAILED_KWARGS)
        dumped = trace.model_dump(mode="json", exclude_none=True)
        assert dumped["failure_reason"] == "internal_evaluation_error"

    def test_distinct_from_v01_failure_reason(self) -> None:
        # v0.1.0 has no closed FailureReason enum on DecisionTrace/
        # RuleEvaluation at all (its outcome/reason fields are plain
        # strings) — confirm TraceFailureReason is not any such symbol and
        # is defined in this module, not audit.trace.
        assert TraceFailureReason.__module__ == "basis_core.audit.operation_aware.evaluation_trace"


# ══════════════════════════════════════════════════════════════════════════
# bundle_applicability (TraceBundleApplicability)
# ══════════════════════════════════════════════════════════════════════════


class TestBundleApplicability:
    @pytest.mark.parametrize("applicability", ["applicable", "not_applicable"])
    def test_every_published_value_accepted_in_valid_combination(self, applicability: str) -> None:
        outcome = "not_applicable" if applicability == "not_applicable" else "allow"
        trace = EvaluationTrace(
            **dict(
                _MINIMAL_COMPLETED_ALLOW_KWARGS,
                outcome=outcome,
                bundle_applicability=applicability,
            )
        )
        assert trace.bundle_applicability == TraceBundleApplicability(applicability)

    def test_null_accepted_when_evaluation_failed_before_applicability_determined(self) -> None:
        trace = EvaluationTrace(**_MINIMAL_FAILED_KWARGS)
        assert trace.bundle_applicability is None

    @pytest.mark.parametrize("applicability", ["unknown", "indeterminate", ""])
    def test_unsupported_values_rejected(self, applicability: str) -> None:
        with pytest.raises(ValidationError):
            EvaluationTrace(
                **dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, bundle_applicability=applicability)
            )

    @pytest.mark.parametrize("applicability", ["APPLICABLE", "Not_Applicable"])
    def test_case_variants_rejected(self, applicability: str) -> None:
        with pytest.raises(ValidationError):
            EvaluationTrace(
                **dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, bundle_applicability=applicability)
            )

    def test_missing_bundle_applicability_key_rejected(self) -> None:
        kwargs = dict(_MINIMAL_COMPLETED_ALLOW_KWARGS)
        del kwargs["bundle_applicability"]
        with pytest.raises(ValidationError):
            EvaluationTrace(**kwargs)

    def test_bundle_applicability_serializes_exactly(self) -> None:
        trace = EvaluationTrace(**_MINIMAL_COMPLETED_ALLOW_KWARGS)
        dumped = trace.model_dump(mode="json")
        assert dumped["bundle_applicability"] == "applicable"


# ══════════════════════════════════════════════════════════════════════════
# bundle_id / bundle_version
# ══════════════════════════════════════════════════════════════════════════


class TestBundleIdentity:
    def test_bundle_id_and_version_optional_default_none(self) -> None:
        trace = EvaluationTrace(**_MINIMAL_COMPLETED_ALLOW_KWARGS)
        assert trace.bundle_id is None
        assert trace.bundle_version is None

    def test_valid_bundle_id_and_version_accepted(self) -> None:
        trace = EvaluationTrace(
            **dict(
                _MINIMAL_COMPLETED_ALLOW_KWARGS,
                bundle_id="baseline-read-only-telemetry",
                bundle_version="1.0.0",
            )
        )
        assert trace.bundle_id == "baseline-read-only-telemetry"
        assert trace.bundle_version == "1.0.0"

    def test_empty_bundle_id_rejected(self) -> None:
        with pytest.raises(ValidationError):
            EvaluationTrace(**dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, bundle_id=""))

    @pytest.mark.parametrize("version", ["v1", "1.0", "1.0.0.0", "1.0.0-rc1", "latest"])
    def test_invalid_bundle_version_rejected(self, version: str) -> None:
        with pytest.raises(ValidationError):
            EvaluationTrace(**dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, bundle_version=version))


# ══════════════════════════════════════════════════════════════════════════
# Evaluation-state matrix — published cross-field invariants
# ══════════════════════════════════════════════════════════════════════════


class TestEvaluationStateMatrix:
    """Directly exercises every state combination named by the roadmap
    (Section I) and the vendored contract's `constraints` block."""

    # ── Valid combinations ───────────────────────────────────────────────

    def test_completed_allow_valid(self) -> None:
        EvaluationTrace(
            **dict(
                _MINIMAL_COMPLETED_ALLOW_KWARGS, outcome="allow", bundle_applicability="applicable"
            )
        )

    def test_completed_deny_valid(self) -> None:
        EvaluationTrace(
            **dict(
                _MINIMAL_COMPLETED_ALLOW_KWARGS, outcome="deny", bundle_applicability="applicable"
            )
        )

    def test_completed_not_applicable_valid(self) -> None:
        EvaluationTrace(
            **dict(
                _MINIMAL_COMPLETED_ALLOW_KWARGS,
                outcome="not_applicable",
                bundle_applicability="not_applicable",
            )
        )

    def test_failed_null_outcome_valid(self) -> None:
        EvaluationTrace(**_MINIMAL_FAILED_KWARGS)

    # ── Invalid combinations ─────────────────────────────────────────────

    def test_completed_null_outcome_invalid(self) -> None:
        with pytest.raises(ValidationError):
            EvaluationTrace(**dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, outcome=None))

    def test_failed_allow_invalid(self) -> None:
        with pytest.raises(ValidationError):
            EvaluationTrace(**dict(_MINIMAL_FAILED_KWARGS, outcome="allow"))

    def test_failed_deny_invalid(self) -> None:
        with pytest.raises(ValidationError):
            EvaluationTrace(**dict(_MINIMAL_FAILED_KWARGS, outcome="deny"))

    def test_failed_not_applicable_invalid(self) -> None:
        with pytest.raises(ValidationError):
            EvaluationTrace(**dict(_MINIMAL_FAILED_KWARGS, outcome="not_applicable"))

    # ── outcome / bundle_applicability agreement (completed only) ───────

    def test_completed_not_applicable_outcome_with_applicable_bundle_invalid(self) -> None:
        with pytest.raises(ValidationError):
            EvaluationTrace(
                **dict(
                    _MINIMAL_COMPLETED_ALLOW_KWARGS,
                    outcome="not_applicable",
                    bundle_applicability="applicable",
                )
            )

    def test_completed_allow_outcome_with_not_applicable_bundle_invalid(self) -> None:
        with pytest.raises(ValidationError):
            EvaluationTrace(
                **dict(
                    _MINIMAL_COMPLETED_ALLOW_KWARGS,
                    outcome="allow",
                    bundle_applicability="not_applicable",
                )
            )

    def test_agreement_not_required_while_failed(self) -> None:
        # A failure inside an already-applicable bundle: bundle_applicability
        # remains "applicable" even though outcome is null (evaluation_status
        # failed) — this is explicitly permitted, not an agreement violation.
        trace = EvaluationTrace(**dict(_MINIMAL_FAILED_KWARGS, bundle_applicability="applicable"))
        assert trace.bundle_applicability is TraceBundleApplicability.APPLICABLE
        assert trace.outcome is None

    # ── not_applicable bundle requires empty rule_evidence ──────────────

    def test_not_applicable_bundle_with_empty_rule_evidence_valid(self) -> None:
        EvaluationTrace(
            **dict(
                _MINIMAL_COMPLETED_ALLOW_KWARGS,
                outcome="not_applicable",
                bundle_applicability="not_applicable",
                rule_evidence=[],
            )
        )

    def test_not_applicable_bundle_with_non_empty_rule_evidence_invalid(self) -> None:
        with pytest.raises(ValidationError):
            EvaluationTrace(
                **dict(
                    _MINIMAL_COMPLETED_ALLOW_KWARGS,
                    outcome="not_applicable",
                    bundle_applicability="not_applicable",
                    rule_evidence=[dict(_MINIMAL_RULE_EVIDENCE_KWARGS, rule_result="skipped")],
                )
            )

    # ── rule_result: error forces evaluation_status: failed ─────────────

    def test_rule_error_with_failed_status_valid(self) -> None:
        trace = EvaluationTrace(
            **dict(
                _MINIMAL_FAILED_KWARGS,
                bundle_applicability="applicable",
                rule_evidence=[dict(_MINIMAL_RULE_EVIDENCE_KWARGS, rule_result="error")],
            )
        )
        assert trace.evaluation_status is EvaluationStatus.FAILED

    def test_rule_error_with_completed_status_invalid(self) -> None:
        with pytest.raises(ValidationError):
            EvaluationTrace(
                **dict(
                    _MINIMAL_COMPLETED_ALLOW_KWARGS,
                    rule_evidence=[dict(_MINIMAL_RULE_EVIDENCE_KWARGS, rule_result="error")],
                )
            )

    def test_rule_error_does_not_require_condition_results(self) -> None:
        # The invariant is keyed on rule_result: error alone; a bare error
        # entry with no condition_results still forces evaluation_status:
        # failed.
        trace = EvaluationTrace(
            **dict(
                _MINIMAL_FAILED_KWARGS,
                bundle_applicability="applicable",
                rule_evidence=[{"rule_id": "rule-1", "effect": "deny", "rule_result": "error"}],
            )
        )
        assert len(trace.rule_evidence) == 1


# ══════════════════════════════════════════════════════════════════════════
# rule_evidence
# ══════════════════════════════════════════════════════════════════════════


class TestRuleEvidence:
    def test_rule_evidence_is_required(self) -> None:
        kwargs = dict(_MINIMAL_COMPLETED_ALLOW_KWARGS)
        del kwargs["rule_evidence"]
        with pytest.raises(ValidationError):
            EvaluationTrace(**kwargs)

    def test_empty_rule_evidence_is_valid(self) -> None:
        trace = EvaluationTrace(**_MINIMAL_COMPLETED_ALLOW_KWARGS)
        assert trace.rule_evidence == []

    def test_valid_nested_rule_evidence_accepted_and_typed(self) -> None:
        trace = EvaluationTrace(
            **dict(
                _MINIMAL_COMPLETED_ALLOW_KWARGS,
                rule_evidence=[_MINIMAL_RULE_EVIDENCE_KWARGS],
            )
        )
        assert len(trace.rule_evidence) == 1
        assert type(trace.rule_evidence[0]) is TraceRuleEvidence
        assert trace.rule_evidence[0].rule_id == "rule-1"

    def test_invalid_nested_rule_evidence_rejected_through_pr24_model(self) -> None:
        malformed = {"rule_id": "rule-1", "effect": "allow", "rule_result": "passed"}
        with pytest.raises(ValidationError):
            EvaluationTrace(**dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, rule_evidence=[malformed]))

    def test_duplicate_rule_id_within_rule_evidence_rejected(self) -> None:
        entries = [
            {"rule_id": "rule-duplicate", "effect": "allow", "rule_result": "matched"},
            {"rule_id": "rule-duplicate", "effect": "deny", "rule_result": "not_matched"},
        ]
        with pytest.raises(ValidationError):
            EvaluationTrace(**dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, rule_evidence=entries))

    def test_unique_rule_ids_across_multiple_entries_accepted(self) -> None:
        entries = [
            {"rule_id": "rule-a", "effect": "allow", "rule_result": "matched"},
            {"rule_id": "rule-b", "effect": "deny", "rule_result": "not_matched"},
        ]
        trace = EvaluationTrace(**dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, rule_evidence=entries))
        assert len(trace.rule_evidence) == 2

    def test_nested_condition_results_reconstruct_through_pr24(self) -> None:
        entry = {
            "rule_id": "rule-deny-elevated-risk",
            "effect": "deny",
            "rule_result": "error",
            "condition_results": [
                {
                    "condition_id": "cond-risk-score-high",
                    "result": "error",
                    "reason_code": "condition_type_mismatch",
                }
            ],
        }
        trace = EvaluationTrace(
            **dict(
                _MINIMAL_FAILED_KWARGS,
                bundle_applicability="applicable",
                rule_evidence=[entry],
            )
        )
        (rule,) = trace.rule_evidence
        assert rule.condition_results is not None
        assert rule.condition_results[0].condition_id == "cond-risk-score-high"

    def test_nested_rule_evidence_serializes_exactly(self) -> None:
        trace = EvaluationTrace(
            **dict(
                _MINIMAL_COMPLETED_ALLOW_KWARGS,
                rule_evidence=[
                    {
                        "rule_id": "rule-1",
                        "effect": "allow",
                        "rule_result": "matched",
                        "reason_code": "allow_rule_matched",
                    }
                ],
            )
        )
        dumped = trace.model_dump(mode="json", exclude_none=True)
        assert dumped["rule_evidence"] == [
            {
                "rule_id": "rule-1",
                "effect": "allow",
                "rule_result": "matched",
                "reason_code": "allow_rule_matched",
            }
        ]


# ══════════════════════════════════════════════════════════════════════════
# Deterministic ordering — rule_evidence order is preserved, never sorted
# ══════════════════════════════════════════════════════════════════════════


class TestDeterministicOrdering:
    """`rule_evidence` order is supplied by the caller and preserved
    exactly by this model — see the module docstring, "Ordering." Uses
    deliberately non-lexical rule IDs so a passing test cannot be explained
    by coincidental alphabetical agreement."""

    _ENTRIES = [
        {"rule_id": "rule-z", "effect": "allow", "rule_result": "matched"},
        {"rule_id": "rule-a", "effect": "deny", "rule_result": "not_matched"},
        {"rule_id": "rule-m", "effect": "allow", "rule_result": "skipped"},
    ]

    def test_supplied_order_is_preserved_on_construction(self) -> None:
        trace = EvaluationTrace(
            **dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, rule_evidence=self._ENTRIES)
        )
        assert [e.rule_id for e in trace.rule_evidence] == ["rule-z", "rule-a", "rule-m"]

    def test_serialization_preserves_supplied_order(self) -> None:
        trace = EvaluationTrace(
            **dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, rule_evidence=self._ENTRIES)
        )
        dumped = trace.model_dump(mode="json", exclude_none=True)
        assert [e["rule_id"] for e in dumped["rule_evidence"]] == ["rule-z", "rule-a", "rule-m"]

    def test_repeated_serialization_produces_the_same_order(self) -> None:
        trace = EvaluationTrace(
            **dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, rule_evidence=self._ENTRIES)
        )
        first = trace.model_dump(mode="json", exclude_none=True)
        second = trace.model_dump(mode="json", exclude_none=True)
        assert first == second
        assert [e["rule_id"] for e in first["rule_evidence"]] == ["rule-z", "rule-a", "rule-m"]

    def test_round_trip_preserves_order(self) -> None:
        trace = EvaluationTrace(
            **dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, rule_evidence=self._ENTRIES)
        )
        dumped = trace.model_dump(mode="json", exclude_none=True)
        restored = EvaluationTrace.model_validate(dumped)
        assert [e.rule_id for e in restored.rule_evidence] == ["rule-z", "rule-a", "rule-m"]
        assert restored == trace

    def test_model_does_not_sort_by_rule_id(self) -> None:
        trace = EvaluationTrace(
            **dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, rule_evidence=self._ENTRIES)
        )
        ids = [e.rule_id for e in trace.rule_evidence]
        assert ids != sorted(ids)

    def test_model_does_not_reorder_by_effect_or_result(self) -> None:
        trace = EvaluationTrace(
            **dict(_MINIMAL_COMPLETED_ALLOW_KWARGS, rule_evidence=self._ENTRIES)
        )
        effects = [e.effect.value for e in trace.rule_evidence]
        results = [e.rule_result.value for e in trace.rule_evidence]
        assert effects == ["allow", "deny", "allow"]
        assert results == ["matched", "not_matched", "skipped"]


# ══════════════════════════════════════════════════════════════════════════
# Boundedness and security
# ══════════════════════════════════════════════════════════════════════════


class TestBoundednessAndSecurity:
    # A representative set spanning distinct prohibited categories (full
    # request/policy content, identity claims, credentials/tokens, raw
    # protocol payloads, raw comparison values, debug/exception artifacts,
    # generic extension bags, and gateway-enforcement facts) rather than an
    # exhaustive enumeration — `extra="forbid"` is one mechanism, so one
    # violation per category is sufficient to prove the architecture guard
    # without repeatedly re-testing the same Pydantic branch.
    @pytest.mark.parametrize(
        "field_name",
        [
            "full_request",
            "policy_document",
            "raw_claims",
            "access_token",
            "raw_payload",
            "actual_value",
            "expected_value",
            "stack_trace",
            "exception",
            "debug",
            "metadata",
            "gateway_enforcement",
        ],
    )
    def test_raw_or_sensitive_field_rejected_as_unknown(self, field_name: str) -> None:
        with pytest.raises(ValidationError):
            EvaluationTrace(**_MINIMAL_COMPLETED_ALLOW_KWARGS, **{field_name: "x"})  # type: ignore[arg-type]

    def test_model_contains_only_published_fields(self) -> None:
        assert set(EvaluationTrace.model_fields) == {
            "trace_id",
            "request_id",
            "correlation_id",
            "evaluation_status",
            "outcome",
            "bundle_applicability",
            "bundle_id",
            "bundle_version",
            "failure_reason",
            "rule_evidence",
            "reason_code",
            "explanation",
        }

    def test_nested_rule_evidence_remains_bounded_by_pr24(self) -> None:
        with pytest.raises(ValidationError):
            EvaluationTrace(
                **dict(
                    _MINIMAL_COMPLETED_ALLOW_KWARGS,
                    rule_evidence=[dict(_MINIMAL_RULE_EVIDENCE_KWARGS, actual_value="alice")],
                )
            )


# ══════════════════════════════════════════════════════════════════════════
# Frozen-model behavior
# ══════════════════════════════════════════════════════════════════════════


class TestImmutability:
    def test_top_level_field_reassignment_rejected(self) -> None:
        trace = EvaluationTrace(**_MINIMAL_COMPLETED_ALLOW_KWARGS)
        with pytest.raises(ValidationError):
            trace.outcome = TraceOutcome.DENY  # type: ignore[misc]


# ══════════════════════════════════════════════════════════════════════════
# v0.1 compatibility — EvaluationTrace is separate from DecisionTrace
# ══════════════════════════════════════════════════════════════════════════


class TestV01Compatibility:
    """Mandatory regression: the existing v0.1.0
    `basis_core.audit.trace.DecisionTrace`/`RuleEvaluation` types are
    untouched by anything added in this PR. `EvaluationTrace` is a distinct
    symbol, never aliased to `DecisionTrace`, never a subclass of it, and
    never exported from the same module."""

    def test_decision_trace_import_still_resolves(self) -> None:
        from basis_core.audit.trace import DecisionTrace

        assert DecisionTrace.__module__ == "basis_core.audit.trace"

    def test_decision_trace_fields_unchanged(self) -> None:
        from basis_core.audit.trace import DecisionTrace

        assert set(DecisionTrace.model_fields) == {
            "final_outcome",
            "evaluated_rules",
            "short_circuited",
        }

    def test_rule_evaluation_fields_unchanged(self) -> None:
        from basis_core.audit.trace import RuleEvaluation

        assert set(RuleEvaluation.model_fields) == {"rule_name", "outcome", "reason"}

    def test_evaluation_trace_is_not_decision_trace(self) -> None:
        from basis_core.audit.trace import DecisionTrace

        assert EvaluationTrace is not DecisionTrace
        assert not issubclass(EvaluationTrace, DecisionTrace)
        assert not issubclass(DecisionTrace, EvaluationTrace)

    def test_audit_package_v01_public_symbols_still_present_unchanged(self) -> None:
        """PR 35 (Milestone 11) additively extends `basis_core.audit.__all__`
        with the operation-aware trace/audit-evidence surface; every v0.1.0
        symbol previously asserted here remains present, in the same
        relative order, unremoved and unrenamed. See
        `tests/test_public_api.py::TestAuditPackage::test_v01_inventory_unchanged`
        for the authoritative harness."""
        import basis_core.audit as audit_package

        v01_symbols = [
            "AuditEvent",
            "AuditEventType",
            "AuditOutcome",
            "AUDIT_SCHEMA_VERSION",
            "AuditWriter",
            "NullAuditWriter",
            "LogAuditWriter",
            "DecisionTrace",
            "RuleEvaluation",
        ]
        assert [name for name in audit_package.__all__ if name in v01_symbols] == v01_symbols


# ══════════════════════════════════════════════════════════════════════════
# Public API boundary — EvaluationTrace graduated to stable public API by PR 35
# ══════════════════════════════════════════════════════════════════════════


class TestPublicAPIBoundary:
    """As of PR 35 (Milestone 11), `EvaluationTrace` and its closed
    vocabularies are stabilized as part of `basis_core.audit`'s
    package-level public API. Supersedes the prior "not prematurely public"
    guard, which asserted the pre-PR-35 state."""

    def test_evaluation_trace_exported_from_basis_core_audit(self) -> None:
        import basis_core.audit as audit_package
        import basis_core.audit.operation_aware.evaluation_trace as concrete

        assert "EvaluationTrace" in audit_package.__all__
        assert audit_package.EvaluationTrace is concrete.EvaluationTrace

    def test_evaluation_trace_not_exported_from_operation_aware_package_init(self) -> None:
        """`basis_core.audit.operation_aware` (the internal orchestration
        subpackage's own __init__) remains un-exported from — only the
        top-level `basis_core.audit` package gained the export."""
        import basis_core.audit.operation_aware as oa_audit_package

        assert not hasattr(oa_audit_package, "EvaluationTrace")


# ══════════════════════════════════════════════════════════════════════════
# Serialization
# ══════════════════════════════════════════════════════════════════════════


class TestSerialization:
    """This model's governed serialization convention deviates from PR 24's
    blanket `model_dump(mode="json", exclude_none=True)` — see the module
    docstring, "Required-nullable serialization," for why:
    `outcome`/`bundle_applicability` are required keys that may hold
    `None`, and must remain present even when `exclude_none=True` is
    requested. Enforced by a `@model_serializer(mode="wrap")`, not a
    `model_dump` override — see `TestRequiredNullableSerializationAcrossEntryPoints`
    and `TestIncludeExcludeTakePrecedence` below for the regression coverage
    that distinguishes those two approaches."""

    def test_plain_model_dump_json_names_every_published_field(self) -> None:
        trace = EvaluationTrace(**_MINIMAL_COMPLETED_ALLOW_KWARGS)
        dumped = trace.model_dump(mode="json")
        assert set(dumped) == {
            "trace_id",
            "request_id",
            "correlation_id",
            "evaluation_status",
            "outcome",
            "bundle_applicability",
            "bundle_id",
            "bundle_version",
            "failure_reason",
            "rule_evidence",
            "reason_code",
            "explanation",
        }

    def test_exclude_none_omits_absent_optional_fields(self) -> None:
        trace = EvaluationTrace(**_MINIMAL_COMPLETED_ALLOW_KWARGS)
        dumped = trace.model_dump(mode="json", exclude_none=True)
        assert dumped == {
            "trace_id": "trace-test-completed-allow",
            "request_id": "oadr-test-completed-allow",
            "evaluation_status": "completed",
            "outcome": "allow",
            "bundle_applicability": "applicable",
            "rule_evidence": [],
        }

    def test_exclude_none_still_retains_required_nullable_keys(self) -> None:
        trace = EvaluationTrace(**_MINIMAL_FAILED_KWARGS)
        dumped = trace.model_dump(mode="json", exclude_none=True)
        assert "outcome" in dumped
        assert dumped["outcome"] is None
        assert "bundle_applicability" in dumped
        assert dumped["bundle_applicability"] is None
        # failure_reason is optional (not required-nullable): present here
        # only because it holds a non-null value in this fixture.
        assert dumped["failure_reason"] == "internal_evaluation_error"

    def test_exclude_none_omits_failure_reason_when_null_and_completed(self) -> None:
        trace = EvaluationTrace(**_MINIMAL_COMPLETED_ALLOW_KWARGS)
        dumped = trace.model_dump(mode="json", exclude_none=True)
        assert "failure_reason" not in dumped

    def test_governed_convention_round_trips_for_full_record(self) -> None:
        trace = EvaluationTrace(
            trace_id="trace-full",
            request_id="oadr-full",
            correlation_id="corr-1",
            evaluation_status="completed",
            outcome="deny",
            bundle_applicability="applicable",
            bundle_id="west-campus-hvac-operations",
            bundle_version="2.3.1",
            rule_evidence=[
                {
                    "rule_id": "rule-west-campus-hvac-allow",
                    "effect": "allow",
                    "rule_result": "matched",
                    "reason_code": "allow_rule_matched",
                },
                {
                    "rule_id": "rule-west-campus-hvac-deny-interlock",
                    "effect": "deny",
                    "rule_result": "matched",
                    "reason_code": "deny_rule_matched",
                },
            ],
            reason_code="deny_rule_matched",
            explanation="Deny precedence applied; an interlock-scoped deny rule matched.",
        )
        dumped = trace.model_dump(mode="json", exclude_none=True)
        restored = EvaluationTrace.model_validate(dumped)
        assert restored == trace


# ══════════════════════════════════════════════════════════════════════════
# Regression: required-nullable keys survive every serialization entry
# point, including nested serialization — the defect a pre-commit review
# found in an earlier `model_dump`-override-based implementation of this
# same requirement (a `model_dump` override never fires for
# `model_dump_json`, and never fires when this model is serialized as a
# nested field of a parent model's own `model_dump`/`model_dump_json`). The
# `@model_serializer(mode="wrap")` implementation is what makes all four
# cases below pass.
# ══════════════════════════════════════════════════════════════════════════


class _TraceWrapper(BaseModel):
    """Local, test-only wrapper standing in for a future parent model (e.g.
    `OperationAwareDecisionResponse`) that embeds `EvaluationTrace`."""

    trace: EvaluationTrace


def _failed_trace_for_serialization_regressions() -> EvaluationTrace:
    return EvaluationTrace(
        trace_id="trace-serialization-regression",
        request_id="oadr-serialization-regression",
        evaluation_status="failed",
        outcome=None,
        bundle_applicability=None,
        failure_reason="internal_evaluation_error",
        rule_evidence=[],
    )


class TestRequiredNullableSerializationAcrossEntryPoints:
    def test_direct_model_dump_retains_required_nullable_keys(self) -> None:
        trace = _failed_trace_for_serialization_regressions()
        dumped = trace.model_dump(mode="json", exclude_none=True)
        assert dumped["outcome"] is None
        assert dumped["bundle_applicability"] is None
        # Unrelated optional-null fields remain omitted.
        assert "correlation_id" not in dumped
        assert "bundle_id" not in dumped
        assert "bundle_version" not in dumped
        assert "reason_code" not in dumped
        assert "explanation" not in dumped

    def test_direct_model_dump_json_retains_required_nullable_keys(self) -> None:
        trace = _failed_trace_for_serialization_regressions()
        raw = trace.model_dump_json(exclude_none=True)
        parsed = json.loads(raw)
        assert "outcome" in parsed
        assert parsed["outcome"] is None
        assert "bundle_applicability" in parsed
        assert parsed["bundle_applicability"] is None
        assert "correlation_id" not in parsed
        assert "explanation" not in parsed

    def test_nested_model_dump_retains_required_nullable_keys(self) -> None:
        trace = _failed_trace_for_serialization_regressions()
        wrapper = _TraceWrapper(trace=trace)
        dumped = wrapper.model_dump(mode="json", exclude_none=True)
        nested = dumped["trace"]
        assert nested["outcome"] is None
        assert nested["bundle_applicability"] is None
        assert "correlation_id" not in nested

    def test_nested_model_dump_json_retains_required_nullable_keys(self) -> None:
        trace = _failed_trace_for_serialization_regressions()
        wrapper = _TraceWrapper(trace=trace)
        raw = wrapper.model_dump_json(exclude_none=True)
        parsed = json.loads(raw)
        nested = parsed["trace"]
        assert "outcome" in nested
        assert nested["outcome"] is None
        assert "bundle_applicability" in nested
        assert nested["bundle_applicability"] is None
        assert "correlation_id" not in nested


# ══════════════════════════════════════════════════════════════════════════
# Regression: explicit include/exclude always wins over required-nullable
# restoration — the second defect the same pre-commit review found (the
# prior `model_dump`-override implementation re-added a key the caller had
# explicitly excluded, and reintroduced keys the caller had not included).
# ══════════════════════════════════════════════════════════════════════════


class TestIncludeExcludeTakePrecedence:
    def test_include_selects_only_named_fields(self) -> None:
        trace = _failed_trace_for_serialization_regressions()
        dumped = trace.model_dump(mode="json", include={"trace_id", "outcome"}, exclude_none=True)
        assert dumped == {"trace_id": "trace-serialization-regression", "outcome": None}

    def test_include_does_not_reintroduce_unselected_required_nullable_fields(self) -> None:
        trace = _failed_trace_for_serialization_regressions()
        dumped = trace.model_dump(mode="json", include={"trace_id"}, exclude_none=True)
        assert dumped == {"trace_id": "trace-serialization-regression"}
        assert "outcome" not in dumped
        assert "bundle_applicability" not in dumped

    def test_exclude_is_not_overridden_by_required_nullable_restoration(self) -> None:
        trace = _failed_trace_for_serialization_regressions()
        dumped = trace.model_dump(mode="json", exclude={"outcome"}, exclude_none=True)
        assert "outcome" not in dumped
        # bundle_applicability was not excluded, so it is still restored.
        assert dumped["bundle_applicability"] is None
