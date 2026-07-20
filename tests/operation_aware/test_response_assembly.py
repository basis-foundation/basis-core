"""
tests/operation_aware/test_response_assembly.py — tests for
`basis_core.evaluation.operation_aware.response_assembly` (Milestone 10, PR
31 of `docs/implementation/basis-core-v0.2-operation-aware-plan.md`:
"Response + AuditEvidence assembly").

Covers pure construction of `OperationAwareDecisionResponse` and
`AuditEvidence` from an already-produced `EvaluationTrace` (and, for
`AuditEvidence`, the `OperationAwareDecisionRequest` that trace answers):
field provenance for every logical evaluation-state category (completed
allow/deny/not_applicable, failed), the explicit vocabulary mapping tables
and their exhaustiveness, request/trace identity safety, matched-rule
projection, determinism, input immutability, and a narrow purity/import
guard. This file does not test `OperationAwareEvaluationEngine` orchestration
(`test_evaluation_engine.py` owns that), `EvaluationTrace`/`AuditEvidence`/
`OperationAwareDecisionResponse` shape validation (their own focused test
files own that), or the full response/trace/audit-evidence agreement matrix
(PR 32, not yet implemented).
"""

from __future__ import annotations

import ast
import inspect
from datetime import datetime, timezone

import pytest

from basis_core.audit.operation_aware.evaluation_trace import (
    EvaluationStatus,
    EvaluationTrace,
    TraceBundleApplicability,
    TraceFailureReason,
    TraceOutcome,
)
from basis_core.audit.operation_aware.trace_rule_evidence import (
    RuleResult,
    TraceRuleEffect,
    TraceRuleEvidence,
)
from basis_core.decisions.operation_aware import (
    OperationAwareDecisionOutcome,
    OperationAwareDecisionRequest,
    OperationAwareEvaluationStatus,
    OperationAwareFailureReason,
)
from basis_core.domain.evidence import (
    AdapterEvidenceReference,
    EvidenceDigest,
    IdentityEvidenceReference,
)
from basis_core.domain.operation_aware_vocabulary import RedactionClassification
from basis_core.evaluation.operation_aware import response_assembly
from basis_core.evaluation.operation_aware.response_assembly import (
    EvaluationArtifactIdentityMismatchError,
    assemble_audit_evidence,
    assemble_operation_aware_decision_response,
)

# ══════════════════════════════════════════════════════════════════════════
# Shared construction helpers
# ══════════════════════════════════════════════════════════════════════════

_RECORDED_AT = datetime(2026, 5, 22, 14, 30, 1, tzinfo=timezone.utc)


def _rule_evidence(
    rule_id: str,
    *,
    effect: TraceRuleEffect = TraceRuleEffect.ALLOW,
    rule_result: RuleResult = RuleResult.MATCHED,
) -> TraceRuleEvidence:
    return TraceRuleEvidence(rule_id=rule_id, effect=effect, rule_result=rule_result)


def _completed_allow_trace(**overrides: object) -> EvaluationTrace:
    kwargs: dict[str, object] = dict(
        trace_id="trace-allow-1",
        request_id="req-allow-1",
        correlation_id="corr-allow-1",
        evaluation_status=EvaluationStatus.COMPLETED,
        outcome=TraceOutcome.ALLOW,
        bundle_applicability=TraceBundleApplicability.APPLICABLE,
        bundle_id="bundle-allow",
        bundle_version="1.0.0",
        failure_reason=None,
        rule_evidence=[_rule_evidence("allow-rule-1")],
        reason_code="allow_rule_matched",
        explanation="Operator role matched an allow rule.",
    )
    kwargs.update(overrides)
    return EvaluationTrace(**kwargs)


def _completed_deny_precedence_trace(**overrides: object) -> EvaluationTrace:
    kwargs: dict[str, object] = dict(
        trace_id="trace-deny-1",
        request_id="req-deny-1",
        correlation_id="corr-deny-1",
        evaluation_status=EvaluationStatus.COMPLETED,
        outcome=TraceOutcome.DENY,
        bundle_applicability=TraceBundleApplicability.APPLICABLE,
        bundle_id="bundle-deny",
        bundle_version="1.0.0",
        failure_reason=None,
        rule_evidence=[
            _rule_evidence("allow-rule-1", effect=TraceRuleEffect.ALLOW),
            _rule_evidence("deny-rule-1", effect=TraceRuleEffect.DENY),
        ],
        reason_code="deny_rule_matched",
        explanation="Deny precedence applied.",
    )
    kwargs.update(overrides)
    return EvaluationTrace(**kwargs)


def _completed_default_deny_trace(**overrides: object) -> EvaluationTrace:
    kwargs: dict[str, object] = dict(
        trace_id="trace-default-deny-1",
        request_id="req-default-deny-1",
        correlation_id=None,
        evaluation_status=EvaluationStatus.COMPLETED,
        outcome=TraceOutcome.DENY,
        bundle_applicability=TraceBundleApplicability.APPLICABLE,
        bundle_id="bundle-default-deny",
        bundle_version="1.0.0",
        failure_reason=None,
        rule_evidence=[
            _rule_evidence(
                "allow-rule-1",
                effect=TraceRuleEffect.ALLOW,
                rule_result=RuleResult.NOT_MATCHED,
            )
        ],
        reason_code="no_allow_rule_matched",
        explanation="No allow rule matched.",
    )
    kwargs.update(overrides)
    return EvaluationTrace(**kwargs)


def _completed_not_applicable_trace(**overrides: object) -> EvaluationTrace:
    kwargs: dict[str, object] = dict(
        trace_id="trace-na-1",
        request_id="req-na-1",
        correlation_id=None,
        evaluation_status=EvaluationStatus.COMPLETED,
        outcome=TraceOutcome.NOT_APPLICABLE,
        bundle_applicability=TraceBundleApplicability.NOT_APPLICABLE,
        bundle_id=None,
        bundle_version=None,
        failure_reason=None,
        rule_evidence=[],
        reason_code="no_applicable_bundle",
        explanation="No policy bundle's scope covers this request.",
    )
    kwargs.update(overrides)
    return EvaluationTrace(**kwargs)


def _failed_trace(
    *,
    failure_reason: TraceFailureReason = TraceFailureReason.POLICY_VALIDATION_FAILURE,
    **overrides: object,
) -> EvaluationTrace:
    kwargs: dict[str, object] = dict(
        trace_id="trace-failed-1",
        request_id="req-failed-1",
        correlation_id=None,
        evaluation_status=EvaluationStatus.FAILED,
        outcome=None,
        bundle_applicability=None,
        bundle_id=None,
        bundle_version=None,
        failure_reason=failure_reason,
        rule_evidence=[],
        reason_code=None,
        explanation="The policy bundle failed validation.",
    )
    kwargs.update(overrides)
    return EvaluationTrace(**kwargs)


def _identity_evidence_reference(**overrides: object) -> IdentityEvidenceReference:
    kwargs: dict[str, object] = dict(
        reference_id="idev-0001",
        evidence_digest=EvidenceDigest(
            algorithm="sha-256",
            value="9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        ),
        identity_source="oidc:https://idp.example.com",
        redaction_classification=RedactionClassification.REFERENCE_ONLY,
    )
    kwargs.update(overrides)
    return IdentityEvidenceReference(**kwargs)


def _adapter_evidence_reference(**overrides: object) -> AdapterEvidenceReference:
    kwargs: dict[str, object] = dict(
        reference_id="adev-0001",
        evidence_digest=EvidenceDigest(
            algorithm="sha-256",
            value="1f825aa2f0020ef7cf91dfa30da4668d791c5d4824fc8e41354b89ec05795ab",
        ),
        adapter_source="basis-adapters:bacnet",
        protocol="bacnet",
        redaction_classification=RedactionClassification.REFERENCE_ONLY,
    )
    kwargs.update(overrides)
    return AdapterEvidenceReference(**kwargs)


def _request(**overrides: object) -> OperationAwareDecisionRequest:
    kwargs: dict[str, object] = dict(
        request_id="req-allow-1",
        subject_id="svc-response-assembly-test",
        action="read:ahu",
    )
    kwargs.update(overrides)
    return OperationAwareDecisionRequest.model_validate(kwargs)


# ══════════════════════════════════════════════════════════════════════════
# Response assembly — evaluation-state categories
# ══════════════════════════════════════════════════════════════════════════


class TestResponseAssemblyCompletedAllow:
    def test_produces_completed_allow(self) -> None:
        trace = _completed_allow_trace()
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        assert response.evaluation_status is OperationAwareEvaluationStatus.COMPLETED
        assert response.outcome is OperationAwareDecisionOutcome.ALLOW
        assert response.failure_reason is None

    def test_bundle_identity_preserved(self) -> None:
        trace = _completed_allow_trace()
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        assert response.bundle_id == trace.bundle_id
        assert response.bundle_version == trace.bundle_version

    def test_reason_code_preserved(self) -> None:
        trace = _completed_allow_trace()
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        assert response.reason_code == trace.reason_code

    def test_explanation_preserved(self) -> None:
        trace = _completed_allow_trace()
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        assert response.explanation == trace.explanation


class TestResponseAssemblyCompletedDeny:
    def test_deny_precedence_produces_completed_deny(self) -> None:
        trace = _completed_deny_precedence_trace()
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        assert response.evaluation_status is OperationAwareEvaluationStatus.COMPLETED
        assert response.outcome is OperationAwareDecisionOutcome.DENY
        assert response.failure_reason is None

    def test_default_deny_produces_completed_deny(self) -> None:
        trace = _completed_default_deny_trace()
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        assert response.evaluation_status is OperationAwareEvaluationStatus.COMPLETED
        assert response.outcome is OperationAwareDecisionOutcome.DENY
        assert response.failure_reason is None


class TestResponseAssemblyCompletedNotApplicable:
    def test_produces_completed_not_applicable(self) -> None:
        trace = _completed_not_applicable_trace()
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        assert response.evaluation_status is OperationAwareEvaluationStatus.COMPLETED
        assert response.outcome is OperationAwareDecisionOutcome.NOT_APPLICABLE
        assert response.failure_reason is None

    def test_not_applicable_is_distinct_from_deny(self) -> None:
        trace = _completed_not_applicable_trace()
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        assert response.outcome is not OperationAwareDecisionOutcome.DENY


class TestResponseAssemblyFailed:
    def test_produces_failed_with_policy_validation_failure(self) -> None:
        trace = _failed_trace(failure_reason=TraceFailureReason.POLICY_VALIDATION_FAILURE)
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        assert response.evaluation_status is OperationAwareEvaluationStatus.FAILED
        assert response.outcome is None
        assert response.failure_reason is OperationAwareFailureReason.POLICY_VALIDATION_FAILURE

    def test_failed_never_becomes_deny(self) -> None:
        trace = _failed_trace()
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        assert response.outcome is not OperationAwareDecisionOutcome.DENY
        assert response.outcome is None

    @pytest.mark.parametrize(
        "trace_failure_reason,response_failure_reason",
        [
            (TraceFailureReason.INVALID_REQUEST, OperationAwareFailureReason.INVALID_REQUEST),
            (
                TraceFailureReason.UNSUPPORTED_SCHEMA_VERSION,
                OperationAwareFailureReason.UNSUPPORTED_SCHEMA_VERSION,
            ),
            (
                TraceFailureReason.INVALID_POLICY_BUNDLE,
                OperationAwareFailureReason.INVALID_POLICY_BUNDLE,
            ),
            (
                TraceFailureReason.POLICY_VALIDATION_FAILURE,
                OperationAwareFailureReason.POLICY_VALIDATION_FAILURE,
            ),
            (
                TraceFailureReason.CONDITION_EVALUATION_ERROR,
                OperationAwareFailureReason.CONDITION_EVALUATION_ERROR,
            ),
            (
                TraceFailureReason.INTERNAL_EVALUATION_ERROR,
                OperationAwareFailureReason.INTERNAL_EVALUATION_ERROR,
            ),
        ],
    )
    def test_all_six_failure_reasons_map_correctly(
        self,
        trace_failure_reason: TraceFailureReason,
        response_failure_reason: OperationAwareFailureReason,
    ) -> None:
        trace = _failed_trace(failure_reason=trace_failure_reason)
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        assert response.failure_reason is response_failure_reason


class TestResponseAssemblyOptionalFields:
    def test_absent_reason_code_remains_absent(self) -> None:
        trace = _completed_allow_trace(reason_code=None)
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        assert response.reason_code is None

    def test_absent_explanation_remains_absent(self) -> None:
        trace = _completed_allow_trace(explanation=None)
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        assert response.explanation is None

    def test_trace_id_preserved(self) -> None:
        trace = _completed_allow_trace(trace_id="trace-distinct-id")
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        assert response.trace_id == "trace-distinct-id"


class TestResponseAssemblyTraceEmbedding:
    def test_reference_only_when_embed_is_false(self) -> None:
        trace = _completed_allow_trace()
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        assert response.trace_id == trace.trace_id
        assert response.evaluation_trace is None

    def test_embedded_when_embed_is_true(self) -> None:
        trace = _completed_allow_trace()
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=True
        )
        assert response.trace_id == trace.trace_id
        assert response.evaluation_trace == trace

    def test_trace_id_always_present_regardless_of_embedding_choice(self) -> None:
        trace = _completed_allow_trace()
        reference_only = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        embedded = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=True
        )
        assert reference_only.trace_id == embedded.trace_id == trace.trace_id


class TestResponseAssemblyNoOutcomeDerivation:
    def test_outcome_comes_from_trace_not_from_rule_evidence(self) -> None:
        """A trace whose `rule_evidence` alone would suggest no matched rule
        at all, but whose already-determined `outcome` is `allow` — the
        response must reflect the trace's own authoritative outcome, not a
        re-scan of `rule_evidence`."""
        trace = _completed_allow_trace(
            rule_evidence=[
                _rule_evidence(
                    "rule-x", effect=TraceRuleEffect.DENY, rule_result=RuleResult.NOT_MATCHED
                )
            ]
        )
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        assert response.outcome is OperationAwareDecisionOutcome.ALLOW


class TestResponseAssemblyDeterminismAndImmutability:
    def test_deterministic_repeat_assembly(self) -> None:
        trace = _completed_allow_trace()
        first = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        second = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        assert first == second

    def test_trace_is_not_mutated(self) -> None:
        trace = _completed_allow_trace()
        before = trace.model_dump(mode="json")
        assemble_operation_aware_decision_response(trace=trace, embed_evaluation_trace=True)
        after = trace.model_dump(mode="json")
        assert before == after


# ══════════════════════════════════════════════════════════════════════════
# AuditEvidence assembly
# ══════════════════════════════════════════════════════════════════════════


class TestAuditEvidenceCallerSuppliedValues:
    def test_evidence_id_preserved(self) -> None:
        trace = _completed_allow_trace()
        request = _request(request_id=trace.request_id, correlation_id=trace.correlation_id)
        evidence = assemble_audit_evidence(
            request=request, trace=trace, evidence_id="audit-evidence-001", recorded_at=_RECORDED_AT
        )
        assert evidence.evidence_id == "audit-evidence-001"

    def test_recorded_at_preserved(self) -> None:
        trace = _completed_allow_trace()
        request = _request(request_id=trace.request_id, correlation_id=trace.correlation_id)
        evidence = assemble_audit_evidence(
            request=request, trace=trace, evidence_id="audit-evidence-002", recorded_at=_RECORDED_AT
        )
        assert evidence.recorded_at == _RECORDED_AT

    def test_no_generated_values(self) -> None:
        """Calling assembly twice with the same caller-supplied
        `evidence_id`/`recorded_at` must produce identical values — proving
        neither is silently generated per call."""
        trace = _completed_allow_trace()
        request = _request(request_id=trace.request_id, correlation_id=trace.correlation_id)
        first = assemble_audit_evidence(
            request=request, trace=trace, evidence_id="audit-evidence-003", recorded_at=_RECORDED_AT
        )
        second = assemble_audit_evidence(
            request=request, trace=trace, evidence_id="audit-evidence-003", recorded_at=_RECORDED_AT
        )
        assert first.evidence_id == second.evidence_id == "audit-evidence-003"
        assert first.recorded_at == second.recorded_at == _RECORDED_AT


class TestAuditEvidenceFieldProvenance:
    def test_request_id_copied_from_trace(self) -> None:
        trace = _completed_allow_trace(request_id="req-provenance-1")
        request = _request(request_id="req-provenance-1", correlation_id=trace.correlation_id)
        evidence = assemble_audit_evidence(
            request=request, trace=trace, evidence_id="ev-1", recorded_at=_RECORDED_AT
        )
        assert evidence.request_id == trace.request_id == "req-provenance-1"

    def test_correlation_id_copied_from_trace(self) -> None:
        trace = _completed_allow_trace(correlation_id="corr-provenance-1")
        request = _request(request_id=trace.request_id, correlation_id="corr-provenance-1")
        evidence = assemble_audit_evidence(
            request=request, trace=trace, evidence_id="ev-2", recorded_at=_RECORDED_AT
        )
        assert evidence.correlation_id == trace.correlation_id == "corr-provenance-1"

    def test_trace_id_copied_from_trace(self) -> None:
        trace = _completed_allow_trace()
        request = _request(request_id=trace.request_id, correlation_id=trace.correlation_id)
        evidence = assemble_audit_evidence(
            request=request, trace=trace, evidence_id="ev-3", recorded_at=_RECORDED_AT
        )
        assert evidence.trace_id == trace.trace_id

    def test_bundle_identity_copied_from_trace(self) -> None:
        trace = _completed_allow_trace()
        request = _request(request_id=trace.request_id, correlation_id=trace.correlation_id)
        evidence = assemble_audit_evidence(
            request=request, trace=trace, evidence_id="ev-4", recorded_at=_RECORDED_AT
        )
        assert evidence.bundle_id == trace.bundle_id
        assert evidence.bundle_version == trace.bundle_version

    def test_reason_code_copied_from_trace(self) -> None:
        trace = _completed_allow_trace()
        request = _request(request_id=trace.request_id, correlation_id=trace.correlation_id)
        evidence = assemble_audit_evidence(
            request=request, trace=trace, evidence_id="ev-5", recorded_at=_RECORDED_AT
        )
        assert evidence.reason_code == trace.reason_code

    def test_explanation_copied_from_trace(self) -> None:
        trace = _completed_allow_trace()
        request = _request(request_id=trace.request_id, correlation_id=trace.correlation_id)
        evidence = assemble_audit_evidence(
            request=request, trace=trace, evidence_id="ev-6", recorded_at=_RECORDED_AT
        )
        assert evidence.explanation == trace.explanation

    def test_evaluation_state_copied_from_trace(self) -> None:
        trace = _failed_trace(failure_reason=TraceFailureReason.INTERNAL_EVALUATION_ERROR)
        request = _request(request_id=trace.request_id, correlation_id=trace.correlation_id)
        evidence = assemble_audit_evidence(
            request=request, trace=trace, evidence_id="ev-7", recorded_at=_RECORDED_AT
        )
        assert evidence.evaluation_status is OperationAwareEvaluationStatus.FAILED
        assert evidence.outcome is None
        assert evidence.failure_reason is OperationAwareFailureReason.INTERNAL_EVALUATION_ERROR


class TestAuditEvidenceEvidenceReferences:
    def test_identity_evidence_reference_copied_by_typed_value(self) -> None:
        trace = _completed_allow_trace()
        identity_ref = _identity_evidence_reference()
        request = _request(
            request_id=trace.request_id,
            correlation_id=trace.correlation_id,
            identity_evidence_reference=identity_ref,
        )
        evidence = assemble_audit_evidence(
            request=request, trace=trace, evidence_id="ev-8", recorded_at=_RECORDED_AT
        )
        assert isinstance(evidence.identity_evidence_reference, IdentityEvidenceReference)
        assert evidence.identity_evidence_reference == identity_ref

    def test_adapter_evidence_reference_copied_by_typed_value(self) -> None:
        trace = _completed_allow_trace()
        adapter_ref = _adapter_evidence_reference()
        request = _request(
            request_id=trace.request_id,
            correlation_id=trace.correlation_id,
            adapter_evidence_reference=adapter_ref,
        )
        evidence = assemble_audit_evidence(
            request=request, trace=trace, evidence_id="ev-9", recorded_at=_RECORDED_AT
        )
        assert isinstance(evidence.adapter_evidence_reference, AdapterEvidenceReference)
        assert evidence.adapter_evidence_reference == adapter_ref

    def test_absent_evidence_references_remain_absent(self) -> None:
        trace = _completed_allow_trace()
        request = _request(request_id=trace.request_id, correlation_id=trace.correlation_id)
        evidence = assemble_audit_evidence(
            request=request, trace=trace, evidence_id="ev-10", recorded_at=_RECORDED_AT
        )
        assert evidence.identity_evidence_reference is None
        assert evidence.adapter_evidence_reference is None


class TestAuditEvidenceMatchedRuleProjection:
    def test_completed_allow_projects_the_matched_rule(self) -> None:
        trace = _completed_allow_trace()
        request = _request(request_id=trace.request_id, correlation_id=trace.correlation_id)
        evidence = assemble_audit_evidence(
            request=request, trace=trace, evidence_id="ev-11", recorded_at=_RECORDED_AT
        )
        assert evidence.matched_rule_ids == ["allow-rule-1"]

    def test_deny_precedence_projects_both_matched_rules_in_order(self) -> None:
        trace = _completed_deny_precedence_trace()
        request = _request(request_id=trace.request_id, correlation_id=trace.correlation_id)
        evidence = assemble_audit_evidence(
            request=request, trace=trace, evidence_id="ev-12", recorded_at=_RECORDED_AT
        )
        assert evidence.matched_rule_ids == ["allow-rule-1", "deny-rule-1"]

    def test_default_deny_produces_no_matched_rules(self) -> None:
        trace = _completed_default_deny_trace()
        request = _request(request_id=trace.request_id, correlation_id=trace.correlation_id)
        evidence = assemble_audit_evidence(
            request=request, trace=trace, evidence_id="ev-13", recorded_at=_RECORDED_AT
        )
        assert evidence.matched_rule_ids == []

    def test_not_applicable_produces_no_matched_rules(self) -> None:
        trace = _completed_not_applicable_trace()
        request = _request(request_id=trace.request_id, correlation_id=trace.correlation_id)
        evidence = assemble_audit_evidence(
            request=request, trace=trace, evidence_id="ev-14", recorded_at=_RECORDED_AT
        )
        assert evidence.matched_rule_ids == []

    def test_failed_validation_produces_no_matched_rules(self) -> None:
        trace = _failed_trace(failure_reason=TraceFailureReason.POLICY_VALIDATION_FAILURE)
        request = _request(request_id=trace.request_id, correlation_id=trace.correlation_id)
        evidence = assemble_audit_evidence(
            request=request, trace=trace, evidence_id="ev-15", recorded_at=_RECORDED_AT
        )
        assert evidence.matched_rule_ids == []

    def test_not_matched_and_skipped_rules_are_excluded_and_order_is_preserved(self) -> None:
        trace = _completed_default_deny_trace(
            rule_evidence=[
                _rule_evidence("matched-1", rule_result=RuleResult.MATCHED),
                _rule_evidence("not-matched-1", rule_result=RuleResult.NOT_MATCHED),
                _rule_evidence("skipped-1", rule_result=RuleResult.SKIPPED),
                _rule_evidence("matched-2", rule_result=RuleResult.MATCHED),
            ]
        )
        request = _request(request_id=trace.request_id, correlation_id=trace.correlation_id)
        evidence = assemble_audit_evidence(
            request=request, trace=trace, evidence_id="ev-16", recorded_at=_RECORDED_AT
        )
        assert evidence.matched_rule_ids == ["matched-1", "matched-2"]

    def test_error_rules_are_excluded(self) -> None:
        trace = _failed_trace(
            failure_reason=TraceFailureReason.CONDITION_EVALUATION_ERROR,
            bundle_applicability=TraceBundleApplicability.APPLICABLE,
            bundle_id="bundle-error",
            bundle_version="1.0.0",
            rule_evidence=[_rule_evidence("error-rule-1", rule_result=RuleResult.ERROR)],
        )
        request = _request(request_id=trace.request_id, correlation_id=trace.correlation_id)
        evidence = assemble_audit_evidence(
            request=request, trace=trace, evidence_id="ev-17", recorded_at=_RECORDED_AT
        )
        assert evidence.matched_rule_ids == []

    def test_trace_evidence_order_is_never_resorted(self) -> None:
        trace = _completed_default_deny_trace(
            rule_evidence=[
                _rule_evidence("z-rule", rule_result=RuleResult.MATCHED),
                _rule_evidence("a-rule", rule_result=RuleResult.MATCHED),
            ]
        )
        request = _request(request_id=trace.request_id, correlation_id=trace.correlation_id)
        evidence = assemble_audit_evidence(
            request=request, trace=trace, evidence_id="ev-18", recorded_at=_RECORDED_AT
        )
        assert evidence.matched_rule_ids == ["z-rule", "a-rule"]


class TestAuditEvidenceDeterminismAndImmutability:
    def test_deterministic_repeat_assembly(self) -> None:
        trace = _completed_allow_trace()
        request = _request(request_id=trace.request_id, correlation_id=trace.correlation_id)
        first = assemble_audit_evidence(
            request=request, trace=trace, evidence_id="ev-19", recorded_at=_RECORDED_AT
        )
        second = assemble_audit_evidence(
            request=request, trace=trace, evidence_id="ev-19", recorded_at=_RECORDED_AT
        )
        assert first == second

    def test_request_and_trace_are_not_mutated(self) -> None:
        trace = _completed_allow_trace()
        request = _request(
            request_id=trace.request_id,
            correlation_id=trace.correlation_id,
            identity_evidence_reference=_identity_evidence_reference(),
            adapter_evidence_reference=_adapter_evidence_reference(),
        )
        trace_before = trace.model_dump(mode="json")
        request_before = request.model_dump(mode="json")
        assemble_audit_evidence(
            request=request, trace=trace, evidence_id="ev-20", recorded_at=_RECORDED_AT
        )
        assert trace.model_dump(mode="json") == trace_before
        assert request.model_dump(mode="json") == request_before


# ══════════════════════════════════════════════════════════════════════════
# Request/trace identity safety
# ══════════════════════════════════════════════════════════════════════════


class TestIdentityMismatch:
    def test_request_id_mismatch_raises(self) -> None:
        trace = _completed_allow_trace(request_id="req-trace-side")
        request = _request(request_id="req-different-side", correlation_id=trace.correlation_id)
        with pytest.raises(EvaluationArtifactIdentityMismatchError) as exc_info:
            assemble_audit_evidence(
                request=request, trace=trace, evidence_id="ev-mismatch-1", recorded_at=_RECORDED_AT
            )
        assert "request_id" in str(exc_info.value)

    def test_correlation_id_mismatch_raises(self) -> None:
        trace = _completed_allow_trace(
            request_id="req-corr-mismatch", correlation_id="corr-trace-side"
        )
        request = _request(request_id="req-corr-mismatch", correlation_id="corr-different-side")
        with pytest.raises(EvaluationArtifactIdentityMismatchError) as exc_info:
            assemble_audit_evidence(
                request=request, trace=trace, evidence_id="ev-mismatch-2", recorded_at=_RECORDED_AT
            )
        assert "correlation_id" in str(exc_info.value)

    def test_none_vs_non_none_correlation_id_is_a_mismatch(self) -> None:
        trace = _completed_allow_trace(request_id="req-none-mismatch", correlation_id=None)
        request = _request(request_id="req-none-mismatch", correlation_id="corr-present")
        with pytest.raises(EvaluationArtifactIdentityMismatchError):
            assemble_audit_evidence(
                request=request, trace=trace, evidence_id="ev-mismatch-3", recorded_at=_RECORDED_AT
            )

    def test_matching_identity_does_not_raise(self) -> None:
        trace = _completed_allow_trace(request_id="req-match", correlation_id="corr-match")
        request = _request(request_id="req-match", correlation_id="corr-match")
        assemble_audit_evidence(
            request=request, trace=trace, evidence_id="ev-match-1", recorded_at=_RECORDED_AT
        )

    def test_matching_none_correlation_ids_do_not_raise(self) -> None:
        trace = _completed_allow_trace(request_id="req-match-none", correlation_id=None)
        request = _request(request_id="req-match-none", correlation_id=None)
        assemble_audit_evidence(
            request=request, trace=trace, evidence_id="ev-match-2", recorded_at=_RECORDED_AT
        )

    def test_mismatch_message_contains_no_raw_evidence_reference_content(self) -> None:
        """The error message names identifiers only — never the request's
        evidence-reference content (digest values, identity/adapter source
        labels)."""
        trace = _completed_allow_trace(request_id="req-evidence-mismatch")
        identity_ref = _identity_evidence_reference(
            evidence_digest=EvidenceDigest(
                algorithm="sha-256",
                value="deadbeefcafebabe00112233445566778899aabbccddeeff0011223344",
            )
        )
        request = _request(
            request_id="req-different-evidence-mismatch",
            correlation_id=trace.correlation_id,
            identity_evidence_reference=identity_ref,
        )
        with pytest.raises(EvaluationArtifactIdentityMismatchError) as exc_info:
            assemble_audit_evidence(
                request=request, trace=trace, evidence_id="ev-mismatch-4", recorded_at=_RECORDED_AT
            )
        message = str(exc_info.value)
        assert "deadbeefcafebabe" not in message
        assert "oidc:https://idp.example.com" not in message


# ══════════════════════════════════════════════════════════════════════════
# Mapping exhaustiveness
# ══════════════════════════════════════════════════════════════════════════


class TestMappingExhaustiveness:
    def test_every_evaluation_status_member_is_mapped(self) -> None:
        assert set(EvaluationStatus) == set(
            response_assembly._EVALUATION_STATUS_TO_RESPONSE_STATUS.keys()
        )
        assert set(response_assembly._EVALUATION_STATUS_TO_RESPONSE_STATUS.values()) == set(
            OperationAwareEvaluationStatus
        )

    def test_every_trace_outcome_member_is_mapped(self) -> None:
        assert set(TraceOutcome) == set(response_assembly._TRACE_OUTCOME_TO_RESPONSE_OUTCOME.keys())
        assert set(response_assembly._TRACE_OUTCOME_TO_RESPONSE_OUTCOME.values()) == set(
            OperationAwareDecisionOutcome
        )

    def test_every_trace_failure_reason_member_is_mapped(self) -> None:
        assert set(TraceFailureReason) == set(
            response_assembly._TRACE_FAILURE_REASON_TO_RESPONSE_FAILURE_REASON.keys()
        )
        assert set(
            response_assembly._TRACE_FAILURE_REASON_TO_RESPONSE_FAILURE_REASON.values()
        ) == set(OperationAwareFailureReason)

    def test_mapping_completeness_fails_if_a_member_is_missing(self) -> None:
        incomplete = dict(response_assembly._EVALUATION_STATUS_TO_RESPONSE_STATUS)
        del incomplete[EvaluationStatus.COMPLETED]
        assert set(EvaluationStatus) != set(incomplete.keys())

    def test_no_value_coercion_is_used_as_the_mapping_implementation(self) -> None:
        """Detects the `TargetEnum(source.value)` anti-pattern via AST (a
        call whose argument is a `.value` attribute access) rather than a
        blunt substring scan, which would also (falsely) flag this module's
        own docstring prose describing the anti-pattern to avoid."""
        source = inspect.getsource(response_assembly)
        tree = ast.parse(source)
        coercions = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and any(isinstance(arg, ast.Attribute) and arg.attr == "value" for arg in node.args)
        ]
        assert coercions == []


# ══════════════════════════════════════════════════════════════════════════
# Purity guard
# ══════════════════════════════════════════════════════════════════════════


class TestPurityGuard:
    def test_module_does_not_import_forbidden_layers_or_libraries(self) -> None:
        source = inspect.getsource(response_assembly)
        tree = ast.parse(source)
        imported_modules: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                imported_modules.append(node.module)
            elif isinstance(node, ast.Import):
                imported_modules.extend(alias.name for alias in node.names)

        forbidden_prefixes = (
            "uuid",
            "random",
            "os",
            "pathlib",
            "socket",
            "requests",
            "subprocess",
            "sqlite3",
            "psycopg2",
            "sqlalchemy",
            "pymongo",
            "redis",
            "basis_core.policy",
            "basis_core.adapters",
            "basis_core.enforcement",
        )
        violations = [
            module
            for module in imported_modules
            if any(
                module == prefix or module.startswith(prefix + ".") for prefix in forbidden_prefixes
            )
        ]
        assert violations == [], f"response_assembly.py imports a forbidden module: {violations}"

    def test_no_clock_call(self) -> None:
        """`datetime` itself is a legitimate import (the `recorded_at`
        parameter's type), but `datetime.now`/`.utcnow`/`.today` must never
        be called — `recorded_at` is caller-supplied only."""
        source = inspect.getsource(response_assembly)
        tree = ast.parse(source)
        clock_calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"now", "utcnow", "today"}
        ]
        assert clock_calls == []

    def test_module_defines_no_persistence_or_writer_function(self) -> None:
        source = inspect.getsource(response_assembly)
        tree = ast.parse(source)
        forbidden_names = {"write", "save", "store", "append", "publish", "emit", "persist"}
        defined_names = {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        assert defined_names.isdisjoint(forbidden_names)

    def test_module_does_not_import_adapters_or_enforcement(self) -> None:
        source = inspect.getsource(response_assembly)
        tree = ast.parse(source)
        imported_modules: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                imported_modules.append(node.module)
            elif isinstance(node, ast.Import):
                imported_modules.extend(alias.name for alias in node.names)
        assert not any(m.startswith("basis_core.adapters") for m in imported_modules)
        assert not any(m.startswith("basis_core.enforcement") for m in imported_modules)

    def test_module_does_not_import_policy(self) -> None:
        """The already-produced `EvaluationTrace` contains every final
        evaluation fact this module needs — no policy-owned type or
        operation is required to assemble either artifact."""
        source = inspect.getsource(response_assembly)
        tree = ast.parse(source)
        imported_modules: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                imported_modules.append(node.module)
            elif isinstance(node, ast.Import):
                imported_modules.extend(alias.name for alias in node.names)
        assert not any(m.startswith("basis_core.policy") for m in imported_modules)


# ══════════════════════════════════════════════════════════════════════════
# Engine/policy-recalculation guard
# ══════════════════════════════════════════════════════════════════════════


class TestNoEngineOrPolicyInvocation:
    def test_module_does_not_import_the_evaluation_engine(self) -> None:
        """The module's own docstring names `OperationAwareEvaluationEngine`
        in prose (explaining what produces the `EvaluationTrace` this module
        consumes) — a blunt substring scan would falsely flag that prose, so
        this checks the actual import statements via AST instead."""
        source = inspect.getsource(response_assembly)
        tree = ast.parse(source)
        imported_names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                imported_names.update(alias.name for alias in node.names)
            elif isinstance(node, ast.Import):
                imported_names.update(alias.name for alias in node.names)
        assert "OperationAwareEvaluationEngine" not in imported_names

        imported_modules: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                imported_modules.append(node.module)
            elif isinstance(node, ast.Import):
                imported_modules.extend(alias.name for alias in node.names)
        assert not any(
            m == "basis_core.evaluation.operation_aware.engine" for m in imported_modules
        )

    def test_module_defines_no_reusable_agreement_validator(self) -> None:
        """PR 31 must not introduce a general-purpose agreement/validation
        helper — that is PR 32's scope. Confirms none of the forbidden names
        the brief specifically calls out are defined here."""
        source = inspect.getsource(response_assembly)
        tree = ast.parse(source)
        forbidden_names = {
            "validate_agreement",
            "assert_consistent",
            "reconcile",
            "synchronize",
            "normalize_artifacts",
        }
        defined_names = {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        assert defined_names.isdisjoint(forbidden_names)
