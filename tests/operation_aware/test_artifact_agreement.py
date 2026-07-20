"""
tests/operation_aware/test_artifact_agreement.py — response/trace/AuditEvidence
agreement invariant tests (Milestone 10, PR 32 of
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`: "Response/
trace/AuditEvidence agreement invariant tests").

This module proves, independently of PR 31's own implementation, that
`assemble_operation_aware_decision_response(...)` and
`assemble_audit_evidence(...)` (`basis_core.evaluation.operation_aware.
response_assembly`) always produce an `OperationAwareDecisionResponse`, an
`EvaluationTrace`, and an `AuditEvidence` that agree on every shared field —
identity, evaluation-state, bundle identity, reason code, explanation,
matched-rule projection, and evidence-reference provenance — across both the
reference-only and embedded response forms, across every valid evaluation
state, and after serialization. It also proves these agreement checks
actually *detect* disagreement, via a parameterized negative-mutation matrix
built from `model_copy(update=...)` on otherwise-valid assembled artifacts.

Scope — what this module does and does not do
────────────────────────────────────────────────────────────────────────────
This is unit-level cross-artifact agreement testing. It constructs typed
`EvaluationTrace`/`OperationAwareDecisionRequest` values directly and calls
the real, merged PR 31 assembler functions to produce the response and audit
artifacts under test — it never hand-constructs a response or `AuditEvidence`
for a positive-agreement case. It does not invoke
`OperationAwareEvaluationEngine`, policy aggregation, policy selection,
condition evaluation, enforcement, or `AuditWriter` — engine behavior is
already covered by `test_engine_canonical_shapes.py`/`test_evaluation_engine.py`,
and enforcement/audit-persistence are later, separately-scoped milestones.

This module defines no production agreement framework. `_assert_response_
trace_agree`, `_assert_audit_trace_agree`, `_assert_response_audit_agree`, and
`_assert_complete_artifact_agreement` below are test-local assertion helpers
only — nothing here is imported by, or exported to, any `src/basis_core/`
module. Agreement is guaranteed by construction in PR 31's assemblers; this
module only proves it.

Independent semantic mapping — not PR 31's mapping tables
────────────────────────────────────────────────────────────────────────────
`EvaluationTrace` uses audit-owned local vocabulary (`EvaluationStatus`/
`TraceOutcome`/`TraceFailureReason`, defined in `basis_core.audit.
operation_aware.evaluation_trace`), independently defined there because
`audit/` may import only `domain/` and `decisions/`. `OperationAwareDecisionResponse`/
`AuditEvidence` instead use the decisions-owned vocabulary
(`OperationAwareEvaluationStatus`/`OperationAwareDecisionOutcome`/
`OperationAwareFailureReason`). `response_assembly.py` (PR 31) already defines
three mapping tables between these two families — but importing those tables
here as "the expected answer" would make this module's agreement assertions
tautological (the assembler would always agree with itself). This module
therefore defines its own, independent copies of the same three mapping
tables (`_TRACE_TO_RESPONSE_EVALUATION_STATUS`, `_TRACE_TO_RESPONSE_OUTCOME`,
`_TRACE_TO_RESPONSE_FAILURE_REASON`) below, walks both the source and target
enum memberships to prove each is exhaustive and (where the vocabularies are
bijective) a member-for-member match, and uses only these independent
mappings — never `response_value.value == trace_value.value` string-coercion
comparison — inside the agreement helpers.

No runtime fixture loading
────────────────────────────────────────────────────────────────────────────
This module never imports `yaml`, `tests.helpers.basis_schemas_snapshot`, or
`tests.helpers.operation_aware_contracts`, and never loads or parses a
vendored `tests/fixtures/basis-schemas/v0.2.1/compatibility/*/expected-*.yaml`
file at runtime — a static AST guard at the bottom of this module proves it
mechanically. The vendored compatibility fixtures were inspected (read, not
loaded) only during this PR's authoring to keep the test-owned scenario
values (bundle IDs, rule IDs, reason codes) recognizably aligned with the
canonical vectors; complete canonical-fixture equality remains PR 37.

No gateway-owned facts
────────────────────────────────────────────────────────────────────────────
This module never imports, constructs, or asserts against `GatewayAuditEvent`
or any gateway-owned `enforcement_action` concept — a static guard confirms
this mechanically alongside the fixture-loading guard. For a failed
evaluation, every kernel artifact under test here retains `outcome: null`;
this module never reinterprets a failed evaluation as a fail-closed `deny`.
"""

from __future__ import annotations

import ast
import inspect
import json
import sys
from datetime import datetime, timezone

import pytest
from pydantic import BaseModel, ConfigDict

from basis_core.audit.operation_aware.audit_evidence import AuditEvidence
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
from basis_core.domain.operation_aware_vocabulary import ReasonCode, RedactionClassification
from basis_core.evaluation.operation_aware.response import OperationAwareDecisionResponse
from basis_core.evaluation.operation_aware.response_assembly import (
    assemble_audit_evidence,
    assemble_operation_aware_decision_response,
)

_RECORDED_AT = datetime(2026, 7, 20, 9, 0, 1, tzinfo=timezone.utc)


# ══════════════════════════════════════════════════════════════════════════
# Independent, test-owned semantic mappings — see module docstring
# ══════════════════════════════════════════════════════════════════════════

_TRACE_TO_RESPONSE_EVALUATION_STATUS: dict[EvaluationStatus, OperationAwareEvaluationStatus] = {
    EvaluationStatus.COMPLETED: OperationAwareEvaluationStatus.COMPLETED,
    EvaluationStatus.FAILED: OperationAwareEvaluationStatus.FAILED,
}

_TRACE_TO_RESPONSE_OUTCOME: dict[TraceOutcome, OperationAwareDecisionOutcome] = {
    TraceOutcome.ALLOW: OperationAwareDecisionOutcome.ALLOW,
    TraceOutcome.DENY: OperationAwareDecisionOutcome.DENY,
    TraceOutcome.NOT_APPLICABLE: OperationAwareDecisionOutcome.NOT_APPLICABLE,
}

_TRACE_TO_RESPONSE_FAILURE_REASON: dict[TraceFailureReason, OperationAwareFailureReason] = {
    TraceFailureReason.INVALID_REQUEST: OperationAwareFailureReason.INVALID_REQUEST,
    TraceFailureReason.UNSUPPORTED_SCHEMA_VERSION: (
        OperationAwareFailureReason.UNSUPPORTED_SCHEMA_VERSION
    ),
    TraceFailureReason.INVALID_POLICY_BUNDLE: OperationAwareFailureReason.INVALID_POLICY_BUNDLE,
    TraceFailureReason.POLICY_VALIDATION_FAILURE: (
        OperationAwareFailureReason.POLICY_VALIDATION_FAILURE
    ),
    TraceFailureReason.CONDITION_EVALUATION_ERROR: (
        OperationAwareFailureReason.CONDITION_EVALUATION_ERROR
    ),
    TraceFailureReason.INTERNAL_EVALUATION_ERROR: (
        OperationAwareFailureReason.INTERNAL_EVALUATION_ERROR
    ),
}


def _map_evaluation_status(status: EvaluationStatus) -> OperationAwareEvaluationStatus:
    """Independent table lookup — never `.value` string coercion."""
    return _TRACE_TO_RESPONSE_EVALUATION_STATUS[status]


def _map_outcome(outcome: TraceOutcome | None) -> OperationAwareDecisionOutcome | None:
    """`None` is handled explicitly: a failed evaluation's null outcome is
    never looked up in the table."""
    if outcome is None:
        return None
    return _TRACE_TO_RESPONSE_OUTCOME[outcome]


def _map_failure_reason(
    failure_reason: TraceFailureReason | None,
) -> OperationAwareFailureReason | None:
    """`None` is handled explicitly: a completed evaluation's null
    failure_reason is never looked up in the table."""
    if failure_reason is None:
        return None
    return _TRACE_TO_RESPONSE_FAILURE_REASON[failure_reason]


class TestIndependentMappingExhaustiveness:
    def test_evaluation_status_mapping_covers_every_source_member_exactly_once(self) -> None:
        assert set(_TRACE_TO_RESPONSE_EVALUATION_STATUS.keys()) == set(EvaluationStatus)
        assert len(_TRACE_TO_RESPONSE_EVALUATION_STATUS) == len(EvaluationStatus)

    def test_evaluation_status_mapping_covers_every_target_member_exactly_once(self) -> None:
        assert set(_TRACE_TO_RESPONSE_EVALUATION_STATUS.values()) == set(
            OperationAwareEvaluationStatus
        )
        assert len(set(_TRACE_TO_RESPONSE_EVALUATION_STATUS.values())) == len(
            OperationAwareEvaluationStatus
        )

    def test_trace_outcome_mapping_covers_every_source_member_exactly_once(self) -> None:
        assert set(_TRACE_TO_RESPONSE_OUTCOME.keys()) == set(TraceOutcome)
        assert len(_TRACE_TO_RESPONSE_OUTCOME) == len(TraceOutcome)

    def test_trace_outcome_mapping_covers_every_target_member_exactly_once(self) -> None:
        assert set(_TRACE_TO_RESPONSE_OUTCOME.values()) == set(OperationAwareDecisionOutcome)
        assert len(set(_TRACE_TO_RESPONSE_OUTCOME.values())) == len(OperationAwareDecisionOutcome)

    def test_failure_reason_mapping_covers_every_source_member_exactly_once(self) -> None:
        assert set(_TRACE_TO_RESPONSE_FAILURE_REASON.keys()) == set(TraceFailureReason)
        assert len(_TRACE_TO_RESPONSE_FAILURE_REASON) == len(TraceFailureReason)

    def test_failure_reason_mapping_covers_every_target_member_exactly_once(self) -> None:
        assert set(_TRACE_TO_RESPONSE_FAILURE_REASON.values()) == set(OperationAwareFailureReason)
        assert len(set(_TRACE_TO_RESPONSE_FAILURE_REASON.values())) == len(
            OperationAwareFailureReason
        )

    def test_none_outcome_and_failure_reason_are_handled_explicitly(self) -> None:
        assert _map_outcome(None) is None
        assert _map_failure_reason(None) is None

    def test_no_value_coercion_is_used_by_this_modules_own_mapping_functions(self) -> None:
        """This module's own `_map_*` helpers must not fall back to
        `TargetEnum(source.value)` string coercion — detected via AST (a call
        whose argument is a `.value` attribute access), matching the same
        anti-pattern guard `test_response_assembly.py` applies to PR 31's
        mapping functions."""
        source = inspect.getsource(sys.modules[__name__])
        tree = ast.parse(source)
        mapping_function_names = {"_map_evaluation_status", "_map_outcome", "_map_failure_reason"}
        function_defs = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name in mapping_function_names
        ]
        assert len(function_defs) == 3
        for func_def in function_defs:
            coercions = [
                node
                for node in ast.walk(func_def)
                if isinstance(node, ast.Call)
                and any(isinstance(arg, ast.Attribute) and arg.attr == "value" for arg in node.args)
            ]
            assert coercions == [], f"{func_def.name} appears to use .value coercion"


# ══════════════════════════════════════════════════════════════════════════
# Scenario construction helpers (test-local; not imported from PR 31's own
# test module, to keep this module's fixtures independent)
# ══════════════════════════════════════════════════════════════════════════


def _rule_evidence(
    rule_id: str,
    *,
    effect: TraceRuleEffect = TraceRuleEffect.ALLOW,
    rule_result: RuleResult = RuleResult.MATCHED,
) -> TraceRuleEvidence:
    return TraceRuleEvidence(rule_id=rule_id, effect=effect, rule_result=rule_result)


def _completed_allow_trace(**overrides: object) -> EvaluationTrace:
    kwargs: dict[str, object] = dict(
        trace_id="trace-agreement-allow-001",
        request_id="req-agreement-allow-001",
        correlation_id="corr-agreement-allow-001",
        evaluation_status=EvaluationStatus.COMPLETED,
        outcome=TraceOutcome.ALLOW,
        bundle_applicability=TraceBundleApplicability.APPLICABLE,
        bundle_id="bundle-agreement-allow",
        bundle_version="1.0.0",
        failure_reason=None,
        rule_evidence=[_rule_evidence("allow-operator-read-ahu")],
        reason_code="allow_rule_matched",
        explanation="Operator role matched an allow rule for read:ahu.",
    )
    kwargs.update(overrides)
    return EvaluationTrace(**kwargs)


def _completed_explicit_deny_trace(**overrides: object) -> EvaluationTrace:
    kwargs: dict[str, object] = dict(
        trace_id="trace-agreement-deny-precedence-001",
        request_id="req-agreement-deny-precedence-001",
        correlation_id="corr-agreement-deny-precedence-001",
        evaluation_status=EvaluationStatus.COMPLETED,
        outcome=TraceOutcome.DENY,
        bundle_applicability=TraceBundleApplicability.APPLICABLE,
        bundle_id="bundle-agreement-deny-precedence",
        bundle_version="1.0.0",
        failure_reason=None,
        rule_evidence=[
            _rule_evidence("allow-operator-write-hvac-setpoint", effect=TraceRuleEffect.ALLOW),
            _rule_evidence("deny-control-during-interlock", effect=TraceRuleEffect.DENY),
        ],
        reason_code="deny_rule_matched",
        explanation="Deny precedence applied; an interlock-scoped deny rule matched.",
    )
    kwargs.update(overrides)
    return EvaluationTrace(**kwargs)


def _completed_default_deny_trace(**overrides: object) -> EvaluationTrace:
    kwargs: dict[str, object] = dict(
        trace_id="trace-agreement-default-deny-001",
        request_id="req-agreement-default-deny-001",
        correlation_id=None,
        evaluation_status=EvaluationStatus.COMPLETED,
        outcome=TraceOutcome.DENY,
        bundle_applicability=TraceBundleApplicability.APPLICABLE,
        bundle_id="bundle-agreement-default-deny",
        bundle_version="1.0.0",
        failure_reason=None,
        rule_evidence=[
            _rule_evidence(
                "allow-operator-read-ahu-telemetry",
                effect=TraceRuleEffect.ALLOW,
                rule_result=RuleResult.NOT_MATCHED,
            )
        ],
        reason_code="no_allow_rule_matched",
        explanation="No allow rule matched this vendor request; default deny applied.",
    )
    kwargs.update(overrides)
    return EvaluationTrace(**kwargs)


def _completed_not_applicable_trace(**overrides: object) -> EvaluationTrace:
    kwargs: dict[str, object] = dict(
        trace_id="trace-agreement-not-applicable-001",
        request_id="req-agreement-not-applicable-001",
        correlation_id=None,
        evaluation_status=EvaluationStatus.COMPLETED,
        outcome=TraceOutcome.NOT_APPLICABLE,
        bundle_applicability=TraceBundleApplicability.NOT_APPLICABLE,
        bundle_id=None,
        bundle_version=None,
        failure_reason=None,
        rule_evidence=[],
        reason_code="no_applicable_bundle",
        explanation="No policy bundle's scope covers this chiller resource request.",
    )
    kwargs.update(overrides)
    return EvaluationTrace(**kwargs)


def _failed_trace(
    *,
    failure_reason: TraceFailureReason = TraceFailureReason.POLICY_VALIDATION_FAILURE,
    **overrides: object,
) -> EvaluationTrace:
    kwargs: dict[str, object] = dict(
        trace_id="trace-agreement-failed-001",
        request_id="req-agreement-failed-001",
        correlation_id=None,
        evaluation_status=EvaluationStatus.FAILED,
        outcome=None,
        bundle_applicability=None,
        bundle_id=None,
        bundle_version=None,
        failure_reason=failure_reason,
        rule_evidence=[],
        reason_code=None,
        explanation="The policy bundle failed validation because it declared duplicate rule IDs.",
    )
    kwargs.update(overrides)
    return EvaluationTrace(**kwargs)


def _identity_evidence_reference(**overrides: object) -> IdentityEvidenceReference:
    kwargs: dict[str, object] = dict(
        reference_id="idev-agreement-0001",
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
        reference_id="adev-agreement-0001",
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
        request_id="req-agreement-allow-001",
        subject_id="svc-artifact-agreement-test",
        action="read:ahu",
    )
    kwargs.update(overrides)
    return OperationAwareDecisionRequest.model_validate(kwargs)


def _request_for_trace(
    trace: EvaluationTrace, **overrides: object
) -> OperationAwareDecisionRequest:
    """Build a request whose request_id/correlation_id agree with `trace`,
    satisfying `assemble_audit_evidence`'s own identity-agreement guard."""
    kwargs: dict[str, object] = dict(
        request_id=trace.request_id,
        correlation_id=trace.correlation_id,
    )
    kwargs.update(overrides)
    return _request(**kwargs)


def _expected_matched_rule_ids(trace: EvaluationTrace) -> list[str]:
    """Independently derive the expected `AuditEvidence.matched_rule_ids`
    projection: iterate `trace.rule_evidence` in order, include only entries
    whose `rule_result` is `MATCHED`. Never sorted or deduplicated."""
    return [
        entry.rule_id for entry in trace.rule_evidence if entry.rule_result is RuleResult.MATCHED
    ]


# ══════════════════════════════════════════════════════════════════════════
# Test-local agreement assertion helpers
# ══════════════════════════════════════════════════════════════════════════


def _assert_response_trace_agree(
    response: OperationAwareDecisionResponse, trace: EvaluationTrace
) -> None:
    assert response.request_id == trace.request_id, (
        f"request_id mismatch: response.request_id={response.request_id!r} "
        f"trace.request_id={trace.request_id!r}"
    )
    assert response.correlation_id == trace.correlation_id, (
        f"correlation_id mismatch: response.correlation_id={response.correlation_id!r} "
        f"trace.correlation_id={trace.correlation_id!r}"
    )
    expected_status = _map_evaluation_status(trace.evaluation_status)
    assert response.evaluation_status == expected_status, (
        f"evaluation_status mismatch: response.evaluation_status="
        f"{response.evaluation_status!r} mapped(trace.evaluation_status)={expected_status!r}"
    )
    expected_outcome = _map_outcome(trace.outcome)
    assert response.outcome == expected_outcome, (
        f"outcome mismatch: response.outcome={response.outcome!r} "
        f"mapped(trace.outcome)={expected_outcome!r}"
    )
    expected_failure_reason = _map_failure_reason(trace.failure_reason)
    assert response.failure_reason == expected_failure_reason, (
        f"failure_reason mismatch: response.failure_reason={response.failure_reason!r} "
        f"mapped(trace.failure_reason)={expected_failure_reason!r}"
    )
    assert response.bundle_id == trace.bundle_id, (
        f"bundle_id mismatch: response.bundle_id={response.bundle_id!r} "
        f"trace.bundle_id={trace.bundle_id!r}"
    )
    assert response.bundle_version == trace.bundle_version, (
        f"bundle_version mismatch: response.bundle_version={response.bundle_version!r} "
        f"trace.bundle_version={trace.bundle_version!r}"
    )
    assert response.trace_id == trace.trace_id, (
        f"trace_id mismatch: response.trace_id={response.trace_id!r} "
        f"trace.trace_id={trace.trace_id!r}"
    )
    assert response.reason_code == trace.reason_code, (
        f"reason_code mismatch: response.reason_code={response.reason_code!r} "
        f"trace.reason_code={trace.reason_code!r}"
    )
    assert response.explanation == trace.explanation, (
        f"explanation mismatch: response.explanation={response.explanation!r} "
        f"trace.explanation={trace.explanation!r}"
    )
    if response.evaluation_trace is not None:
        assert response.evaluation_trace == trace, (
            "embedded evaluation_trace mismatch: response.evaluation_trace does not equal "
            "the supplied trace"
        )


def _assert_audit_trace_agree(audit: AuditEvidence, trace: EvaluationTrace) -> None:
    assert audit.request_id == trace.request_id, (
        f"request_id mismatch: audit.request_id={audit.request_id!r} "
        f"trace.request_id={trace.request_id!r}"
    )
    assert audit.correlation_id == trace.correlation_id, (
        f"correlation_id mismatch: audit.correlation_id={audit.correlation_id!r} "
        f"trace.correlation_id={trace.correlation_id!r}"
    )
    expected_status = _map_evaluation_status(trace.evaluation_status)
    assert audit.evaluation_status == expected_status, (
        f"evaluation_status mismatch: audit.evaluation_status={audit.evaluation_status!r} "
        f"mapped(trace.evaluation_status)={expected_status!r}"
    )
    expected_outcome = _map_outcome(trace.outcome)
    assert audit.outcome == expected_outcome, (
        f"outcome mismatch: audit.outcome={audit.outcome!r} "
        f"mapped(trace.outcome)={expected_outcome!r}"
    )
    expected_failure_reason = _map_failure_reason(trace.failure_reason)
    assert audit.failure_reason == expected_failure_reason, (
        f"failure_reason mismatch: audit.failure_reason={audit.failure_reason!r} "
        f"mapped(trace.failure_reason)={expected_failure_reason!r}"
    )
    assert audit.bundle_id == trace.bundle_id, (
        f"bundle_id mismatch: audit.bundle_id={audit.bundle_id!r} "
        f"trace.bundle_id={trace.bundle_id!r}"
    )
    assert audit.bundle_version == trace.bundle_version, (
        f"bundle_version mismatch: audit.bundle_version={audit.bundle_version!r} "
        f"trace.bundle_version={trace.bundle_version!r}"
    )
    assert audit.trace_id == trace.trace_id, (
        f"trace_id mismatch: audit.trace_id={audit.trace_id!r} trace.trace_id={trace.trace_id!r}"
    )
    assert audit.reason_code == trace.reason_code, (
        f"reason_code mismatch: audit.reason_code={audit.reason_code!r} "
        f"trace.reason_code={trace.reason_code!r}"
    )
    assert audit.explanation == trace.explanation, (
        f"explanation mismatch: audit.explanation={audit.explanation!r} "
        f"trace.explanation={trace.explanation!r}"
    )


def _assert_response_audit_agree(
    response: OperationAwareDecisionResponse, audit: AuditEvidence
) -> None:
    assert response.request_id == audit.request_id, (
        f"request_id mismatch: response.request_id={response.request_id!r} "
        f"audit.request_id={audit.request_id!r}"
    )
    assert response.correlation_id == audit.correlation_id, (
        f"correlation_id mismatch: response.correlation_id={response.correlation_id!r} "
        f"audit.correlation_id={audit.correlation_id!r}"
    )
    assert response.evaluation_status == audit.evaluation_status, (
        f"evaluation_status mismatch: response.evaluation_status="
        f"{response.evaluation_status!r} audit.evaluation_status={audit.evaluation_status!r}"
    )
    assert response.outcome == audit.outcome, (
        f"outcome mismatch: response.outcome={response.outcome!r} audit.outcome={audit.outcome!r}"
    )
    assert response.failure_reason == audit.failure_reason, (
        f"failure_reason mismatch: response.failure_reason={response.failure_reason!r} "
        f"audit.failure_reason={audit.failure_reason!r}"
    )
    assert response.bundle_id == audit.bundle_id, (
        f"bundle_id mismatch: response.bundle_id={response.bundle_id!r} "
        f"audit.bundle_id={audit.bundle_id!r}"
    )
    assert response.bundle_version == audit.bundle_version, (
        f"bundle_version mismatch: response.bundle_version={response.bundle_version!r} "
        f"audit.bundle_version={audit.bundle_version!r}"
    )
    assert response.trace_id == audit.trace_id, (
        f"trace_id mismatch: response.trace_id={response.trace_id!r} "
        f"audit.trace_id={audit.trace_id!r}"
    )
    assert response.reason_code == audit.reason_code, (
        f"reason_code mismatch: response.reason_code={response.reason_code!r} "
        f"audit.reason_code={audit.reason_code!r}"
    )
    assert response.explanation == audit.explanation, (
        f"explanation mismatch: response.explanation={response.explanation!r} "
        f"audit.explanation={audit.explanation!r}"
    )


def _assert_matched_rule_agreement(audit: AuditEvidence, trace: EvaluationTrace) -> None:
    expected = _expected_matched_rule_ids(trace)
    assert audit.matched_rule_ids == expected, (
        f"matched_rule_ids mismatch: audit.matched_rule_ids={audit.matched_rule_ids!r} "
        f"expected(from trace.rule_evidence)={expected!r}"
    )


def _assert_request_evidence_provenance(
    audit: AuditEvidence, request: OperationAwareDecisionRequest
) -> None:
    assert audit.identity_evidence_reference == request.identity_evidence_reference, (
        "identity_evidence_reference mismatch: audit.identity_evidence_reference="
        f"{audit.identity_evidence_reference!r} "
        f"request.identity_evidence_reference={request.identity_evidence_reference!r}"
    )
    assert audit.adapter_evidence_reference == request.adapter_evidence_reference, (
        "adapter_evidence_reference mismatch: audit.adapter_evidence_reference="
        f"{audit.adapter_evidence_reference!r} "
        f"request.adapter_evidence_reference={request.adapter_evidence_reference!r}"
    )


def _assert_complete_artifact_agreement(
    response: OperationAwareDecisionResponse,
    trace: EvaluationTrace,
    audit: AuditEvidence,
    request: OperationAwareDecisionRequest,
) -> None:
    _assert_response_trace_agree(response, trace)
    _assert_audit_trace_agree(audit, trace)
    _assert_response_audit_agree(response, audit)
    _assert_matched_rule_agreement(audit, trace)
    _assert_request_evidence_provenance(audit, request)


# ══════════════════════════════════════════════════════════════════════════
# Positive scenarios: completed allow / explicit deny / default deny /
# not-applicable / failed — each built from the real trace, then assembled
# through the real PR 31 functions.
# ══════════════════════════════════════════════════════════════════════════

_SCENARIO_TRACE_BUILDERS = {
    "completed_allow": _completed_allow_trace,
    "completed_explicit_deny": _completed_explicit_deny_trace,
    "completed_default_deny": _completed_default_deny_trace,
    "completed_not_applicable": _completed_not_applicable_trace,
    "failed_policy_validation": lambda: _failed_trace(
        failure_reason=TraceFailureReason.POLICY_VALIDATION_FAILURE
    ),
}


class TestScenarioAgreementReferenceOnly:
    @pytest.mark.parametrize("scenario_name", list(_SCENARIO_TRACE_BUILDERS))
    def test_complete_agreement_holds_reference_only(self, scenario_name: str) -> None:
        trace = _SCENARIO_TRACE_BUILDERS[scenario_name]()
        request = _request_for_trace(
            trace,
            identity_evidence_reference=_identity_evidence_reference(),
            adapter_evidence_reference=_adapter_evidence_reference(),
        )
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        audit = assemble_audit_evidence(
            request=request,
            trace=trace,
            evidence_id=f"ev-{scenario_name}",
            recorded_at=_RECORDED_AT,
        )
        assert response.evaluation_trace is None
        assert response.trace_id == trace.trace_id
        _assert_complete_artifact_agreement(response, trace, audit, request)

    @pytest.mark.parametrize("scenario_name", list(_SCENARIO_TRACE_BUILDERS))
    def test_complete_agreement_holds_embedded(self, scenario_name: str) -> None:
        trace = _SCENARIO_TRACE_BUILDERS[scenario_name]()
        request = _request_for_trace(
            trace,
            identity_evidence_reference=_identity_evidence_reference(),
            adapter_evidence_reference=_adapter_evidence_reference(),
        )
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=True
        )
        audit = assemble_audit_evidence(
            request=request,
            trace=trace,
            evidence_id=f"ev-{scenario_name}-embedded",
            recorded_at=_RECORDED_AT,
        )
        assert response.trace_id == trace.trace_id
        assert response.evaluation_trace == trace
        _assert_complete_artifact_agreement(response, trace, audit, request)


class TestEvaluationStateAgreement:
    def test_completed_allow_state(self) -> None:
        trace = _completed_allow_trace()
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        assert response.evaluation_status is OperationAwareEvaluationStatus.COMPLETED
        assert response.outcome is OperationAwareDecisionOutcome.ALLOW
        assert response.failure_reason is None

    def test_completed_explicit_deny_state(self) -> None:
        trace = _completed_explicit_deny_trace()
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        assert response.evaluation_status is OperationAwareEvaluationStatus.COMPLETED
        assert response.outcome is OperationAwareDecisionOutcome.DENY
        assert response.failure_reason is None

    def test_completed_default_deny_state(self) -> None:
        trace = _completed_default_deny_trace()
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        assert response.evaluation_status is OperationAwareEvaluationStatus.COMPLETED
        assert response.outcome is OperationAwareDecisionOutcome.DENY
        assert response.failure_reason is None

    def test_completed_not_applicable_state(self) -> None:
        trace = _completed_not_applicable_trace()
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        assert response.evaluation_status is OperationAwareEvaluationStatus.COMPLETED
        assert response.outcome is OperationAwareDecisionOutcome.NOT_APPLICABLE
        assert response.failure_reason is None

    def test_failed_state_outcome_is_null(self) -> None:
        trace = _failed_trace()
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        assert response.evaluation_status is OperationAwareEvaluationStatus.FAILED
        assert response.outcome is None
        assert response.failure_reason is not None

    def test_failed_evaluation_is_never_represented_as_deny(self) -> None:
        for failure_reason in TraceFailureReason:
            trace = _failed_trace(failure_reason=failure_reason)
            response = assemble_operation_aware_decision_response(
                trace=trace, embed_evaluation_trace=False
            )
            audit = assemble_audit_evidence(
                request=_request_for_trace(trace),
                trace=trace,
                evidence_id=f"ev-never-deny-{failure_reason.value}",
                recorded_at=_RECORDED_AT,
            )
            assert response.outcome is not OperationAwareDecisionOutcome.DENY
            assert response.outcome is None
            assert audit.outcome is not OperationAwareDecisionOutcome.DENY
            assert audit.outcome is None

    def test_not_applicable_is_never_represented_as_deny(self) -> None:
        trace = _completed_not_applicable_trace()
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        audit = assemble_audit_evidence(
            request=_request_for_trace(trace),
            trace=trace,
            evidence_id="ev-na-never-deny",
            recorded_at=_RECORDED_AT,
        )
        assert response.outcome is not OperationAwareDecisionOutcome.DENY
        assert audit.outcome is not OperationAwareDecisionOutcome.DENY

    @pytest.mark.parametrize("scenario_name", list(_SCENARIO_TRACE_BUILDERS))
    def test_response_and_audit_never_drift_from_trace_state(self, scenario_name: str) -> None:
        trace = _SCENARIO_TRACE_BUILDERS[scenario_name]()
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        audit = assemble_audit_evidence(
            request=_request_for_trace(trace),
            trace=trace,
            evidence_id=f"ev-state-drift-{scenario_name}",
            recorded_at=_RECORDED_AT,
        )
        _assert_response_trace_agree(response, trace)
        _assert_audit_trace_agree(audit, trace)


class TestGovernedFailureReasons:
    @pytest.mark.parametrize("failure_reason", list(TraceFailureReason))
    def test_all_six_governed_failure_reasons_agree(
        self, failure_reason: TraceFailureReason
    ) -> None:
        trace = _failed_trace(failure_reason=failure_reason)
        request = _request_for_trace(trace)
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        audit = assemble_audit_evidence(
            request=request,
            trace=trace,
            evidence_id=f"ev-governed-{failure_reason.value}",
            recorded_at=_RECORDED_AT,
        )
        _assert_complete_artifact_agreement(response, trace, audit, request)
        assert response.failure_reason is _map_failure_reason(failure_reason)

    def test_corrected_policy_validation_failure_not_invalid_policy_bundle(self) -> None:
        """The 'duplicate rule_id' semantic-validation scenario is
        `policy_validation_failure`, never the superseded
        `invalid_policy_bundle` classification — matching the vendored
        `invalid-policy-bundle` canonical fixture's own corrected mapping
        (bundle shape was valid; a cross-rule semantic invariant failed)."""
        trace = _failed_trace(failure_reason=TraceFailureReason.POLICY_VALIDATION_FAILURE)
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        assert response.failure_reason is OperationAwareFailureReason.POLICY_VALIDATION_FAILURE
        assert response.failure_reason is not OperationAwareFailureReason.INVALID_POLICY_BUNDLE


# ══════════════════════════════════════════════════════════════════════════
# Reference-only vs. embedded response forms
# ══════════════════════════════════════════════════════════════════════════


class TestResponseTraceEmbeddingForms:
    def test_reference_only_response_omits_embedded_trace(self) -> None:
        trace = _completed_allow_trace()
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        assert response.trace_id == trace.trace_id
        assert response.evaluation_trace is None
        _assert_response_trace_agree(response, trace)

    def test_embedded_response_carries_the_exact_trace(self) -> None:
        trace = _completed_allow_trace()
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=True
        )
        assert response.trace_id == trace.trace_id
        assert response.evaluation_trace == trace
        _assert_response_trace_agree(response, trace)

    def test_reference_only_is_not_treated_as_incomplete(self) -> None:
        """Reference-only is a legitimate, complete response shape — every
        top-level shared field still agrees with the trace and AuditEvidence
        even though the trace itself is not embedded."""
        trace = _completed_allow_trace()
        request = _request_for_trace(trace)
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        audit = assemble_audit_evidence(
            request=request,
            trace=trace,
            evidence_id="ev-ref-only-complete",
            recorded_at=_RECORDED_AT,
        )
        _assert_complete_artifact_agreement(response, trace, audit, request)

    def test_embedding_is_not_required_for_every_response(self) -> None:
        """Both forms are legal per-response choices; this test simply
        proves both can be produced from the same trace without either
        being rejected."""
        trace = _completed_allow_trace()
        reference_only = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        embedded = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=True
        )
        assert reference_only.trace_id == embedded.trace_id == trace.trace_id


# ══════════════════════════════════════════════════════════════════════════
# Matched-rule projection agreement
# ══════════════════════════════════════════════════════════════════════════


class TestMatchedRuleProjectionAgreement:
    def test_allow_matching_rule_appears(self) -> None:
        trace = _completed_allow_trace()
        audit = assemble_audit_evidence(
            request=_request_for_trace(trace),
            trace=trace,
            evidence_id="ev-matched-allow",
            recorded_at=_RECORDED_AT,
        )
        _assert_matched_rule_agreement(audit, trace)
        assert audit.matched_rule_ids == ["allow-operator-read-ahu"]

    def test_deny_precedence_both_matched_rules_appear_in_trace_order(self) -> None:
        trace = _completed_explicit_deny_trace()
        audit = assemble_audit_evidence(
            request=_request_for_trace(trace),
            trace=trace,
            evidence_id="ev-matched-deny-precedence",
            recorded_at=_RECORDED_AT,
        )
        _assert_matched_rule_agreement(audit, trace)
        assert audit.matched_rule_ids == [
            "allow-operator-write-hvac-setpoint",
            "deny-control-during-interlock",
        ]

    def test_default_deny_produces_empty_matched_rule_list(self) -> None:
        trace = _completed_default_deny_trace()
        audit = assemble_audit_evidence(
            request=_request_for_trace(trace),
            trace=trace,
            evidence_id="ev-matched-default-deny",
            recorded_at=_RECORDED_AT,
        )
        _assert_matched_rule_agreement(audit, trace)
        assert audit.matched_rule_ids == []

    def test_not_applicable_produces_empty_matched_rule_list(self) -> None:
        trace = _completed_not_applicable_trace()
        audit = assemble_audit_evidence(
            request=_request_for_trace(trace),
            trace=trace,
            evidence_id="ev-matched-not-applicable",
            recorded_at=_RECORDED_AT,
        )
        _assert_matched_rule_agreement(audit, trace)
        assert audit.matched_rule_ids == []

    def test_failed_evaluation_produces_empty_matched_rule_list(self) -> None:
        trace = _failed_trace()
        audit = assemble_audit_evidence(
            request=_request_for_trace(trace),
            trace=trace,
            evidence_id="ev-matched-failed",
            recorded_at=_RECORDED_AT,
        )
        _assert_matched_rule_agreement(audit, trace)
        assert audit.matched_rule_ids == []

    def test_matched_rule_ids_are_not_inferred_from_outcome_alone(self) -> None:
        """A `deny` outcome may carry both a matched allow and a matched deny
        rule (deny precedence) — the projection must report both, not just
        the rule matching the final outcome."""
        trace = _completed_explicit_deny_trace()
        expected = _expected_matched_rule_ids(trace)
        assert expected == [
            "allow-operator-write-hvac-setpoint",
            "deny-control-during-interlock",
        ]

    def test_order_is_part_of_the_agreement_contract(self) -> None:
        """A negative mutation with matched IDs reversed must be detected as
        disagreement, not treated as an equivalent set."""
        trace = _completed_explicit_deny_trace()
        audit = assemble_audit_evidence(
            request=_request_for_trace(trace),
            trace=trace,
            evidence_id="ev-matched-order",
            recorded_at=_RECORDED_AT,
        )
        reversed_audit = audit.model_copy(
            update={"matched_rule_ids": list(reversed(audit.matched_rule_ids))}
        )
        # Same set, different order — still a mismatch under the ordered
        # agreement contract.
        assert set(reversed_audit.matched_rule_ids) == set(_expected_matched_rule_ids(trace))
        with pytest.raises(AssertionError, match="matched_rule_ids"):
            _assert_matched_rule_agreement(reversed_audit, trace)


# ══════════════════════════════════════════════════════════════════════════
# Request evidence-reference provenance
# ══════════════════════════════════════════════════════════════════════════


class TestRequestEvidenceReferenceProvenance:
    def test_both_references_present(self) -> None:
        trace = _completed_allow_trace()
        identity_ref = _identity_evidence_reference()
        adapter_ref = _adapter_evidence_reference()
        request = _request_for_trace(
            trace, identity_evidence_reference=identity_ref, adapter_evidence_reference=adapter_ref
        )
        audit = assemble_audit_evidence(
            request=request, trace=trace, evidence_id="ev-evidence-both", recorded_at=_RECORDED_AT
        )
        _assert_request_evidence_provenance(audit, request)
        assert audit.identity_evidence_reference == identity_ref
        assert audit.adapter_evidence_reference == adapter_ref

    def test_both_references_absent(self) -> None:
        trace = _completed_allow_trace()
        request = _request_for_trace(trace)
        audit = assemble_audit_evidence(
            request=request, trace=trace, evidence_id="ev-evidence-none", recorded_at=_RECORDED_AT
        )
        _assert_request_evidence_provenance(audit, request)
        assert audit.identity_evidence_reference is None
        assert audit.adapter_evidence_reference is None

    def test_identity_present_adapter_absent(self) -> None:
        trace = _completed_allow_trace()
        identity_ref = _identity_evidence_reference()
        request = _request_for_trace(trace, identity_evidence_reference=identity_ref)
        audit = assemble_audit_evidence(
            request=request,
            trace=trace,
            evidence_id="ev-evidence-identity-only",
            recorded_at=_RECORDED_AT,
        )
        _assert_request_evidence_provenance(audit, request)
        assert audit.identity_evidence_reference == identity_ref
        assert audit.adapter_evidence_reference is None

    def test_adapter_present_identity_absent(self) -> None:
        trace = _completed_allow_trace()
        adapter_ref = _adapter_evidence_reference()
        request = _request_for_trace(trace, adapter_evidence_reference=adapter_ref)
        audit = assemble_audit_evidence(
            request=request,
            trace=trace,
            evidence_id="ev-evidence-adapter-only",
            recorded_at=_RECORDED_AT,
        )
        _assert_request_evidence_provenance(audit, request)
        assert audit.identity_evidence_reference is None
        assert audit.adapter_evidence_reference == adapter_ref

    def test_response_and_trace_do_not_acquire_evidence_reference_fields(self) -> None:
        """The response and trace contracts do not publish
        identity_evidence_reference/adapter_evidence_reference — this is
        AuditEvidence-only provenance."""
        assert "identity_evidence_reference" not in OperationAwareDecisionResponse.model_fields
        assert "adapter_evidence_reference" not in OperationAwareDecisionResponse.model_fields
        assert "identity_evidence_reference" not in EvaluationTrace.model_fields
        assert "adapter_evidence_reference" not in EvaluationTrace.model_fields


# ══════════════════════════════════════════════════════════════════════════
# Artifact-specific fields excluded from agreement
# ══════════════════════════════════════════════════════════════════════════


class TestArtifactSpecificFieldsExcludedFromAgreement:
    def test_evidence_id_has_no_cross_artifact_equivalent(self) -> None:
        """`evidence_id` is a caller-supplied audit-record fact, not shared
        with response or trace."""
        assert "evidence_id" in AuditEvidence.model_fields
        assert "evidence_id" not in OperationAwareDecisionResponse.model_fields
        assert "evidence_id" not in EvaluationTrace.model_fields

    def test_recorded_at_has_no_cross_artifact_equivalent(self) -> None:
        """`recorded_at` is a caller-supplied audit-record fact, not shared
        with response or trace."""
        assert "recorded_at" in AuditEvidence.model_fields
        assert "recorded_at" not in OperationAwareDecisionResponse.model_fields
        assert "recorded_at" not in EvaluationTrace.model_fields

    def test_bundle_applicability_is_trace_only(self) -> None:
        """`bundle_applicability` is a trace explanation fact — not
        published by response or AuditEvidence."""
        assert "bundle_applicability" in EvaluationTrace.model_fields
        assert "bundle_applicability" not in OperationAwareDecisionResponse.model_fields
        assert "bundle_applicability" not in AuditEvidence.model_fields

    def test_rule_evidence_is_trace_only(self) -> None:
        """Complete per-rule evidence is a trace explanation fact —
        AuditEvidence carries only the bounded `matched_rule_ids`
        projection, never full rule_evidence."""
        assert "rule_evidence" in EvaluationTrace.model_fields
        assert "rule_evidence" not in OperationAwareDecisionResponse.model_fields
        assert "rule_evidence" not in AuditEvidence.model_fields

    def test_evaluation_trace_embedding_is_a_response_only_choice(self) -> None:
        """`evaluation_trace` (the embedding field) is an optional response
        embedding choice — not published by AuditEvidence, which references
        a trace only by `trace_id`."""
        assert "evaluation_trace" in OperationAwareDecisionResponse.model_fields
        assert "evaluation_trace" not in AuditEvidence.model_fields


# ══════════════════════════════════════════════════════════════════════════
# Presence semantics
# ══════════════════════════════════════════════════════════════════════════


class TestPresenceSemantics:
    def test_correlation_id_none_agrees_across_all_three_artifacts(self) -> None:
        trace = _completed_not_applicable_trace()
        assert trace.correlation_id is None
        request = _request_for_trace(trace)
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        audit = assemble_audit_evidence(
            request=request, trace=trace, evidence_id="ev-corr-none", recorded_at=_RECORDED_AT
        )
        assert response.correlation_id is None
        assert audit.correlation_id is None
        _assert_response_audit_agree(response, audit)

    def test_correlation_id_present_agrees_across_all_three_artifacts(self) -> None:
        trace = _completed_allow_trace()
        assert trace.correlation_id is not None
        request = _request_for_trace(trace)
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        audit = assemble_audit_evidence(
            request=request, trace=trace, evidence_id="ev-corr-present", recorded_at=_RECORDED_AT
        )
        assert response.correlation_id == audit.correlation_id == trace.correlation_id
        _assert_response_audit_agree(response, audit)

    def test_absent_reason_code_remains_none_everywhere(self) -> None:
        trace = _failed_trace()
        assert trace.reason_code is None
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        audit = assemble_audit_evidence(
            request=_request_for_trace(trace),
            trace=trace,
            evidence_id="ev-reason-code-absent",
            recorded_at=_RECORDED_AT,
        )
        assert response.reason_code is None
        assert audit.reason_code is None

    def test_present_reason_code_agrees_everywhere(self) -> None:
        trace = _completed_allow_trace()
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        audit = assemble_audit_evidence(
            request=_request_for_trace(trace),
            trace=trace,
            evidence_id="ev-reason-code-present",
            recorded_at=_RECORDED_AT,
        )
        assert (
            response.reason_code == audit.reason_code == trace.reason_code == "allow_rule_matched"
        )

    def test_absent_explanation_remains_none_everywhere(self) -> None:
        trace = _completed_allow_trace(explanation=None, reason_code=None)
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        audit = assemble_audit_evidence(
            request=_request_for_trace(trace),
            trace=trace,
            evidence_id="ev-explanation-absent",
            recorded_at=_RECORDED_AT,
        )
        assert response.explanation is None
        assert audit.explanation is None

    def test_present_explanation_agrees_everywhere(self) -> None:
        trace = _completed_allow_trace()
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        audit = assemble_audit_evidence(
            request=_request_for_trace(trace),
            trace=trace,
            evidence_id="ev-explanation-present",
            recorded_at=_RECORDED_AT,
        )
        assert response.explanation == audit.explanation == trace.explanation is not None

    def test_empty_matched_rule_list_is_a_list_not_none(self) -> None:
        trace = _completed_not_applicable_trace()
        audit = assemble_audit_evidence(
            request=_request_for_trace(trace),
            trace=trace,
            evidence_id="ev-empty-matched-not-none",
            recorded_at=_RECORDED_AT,
        )
        assert audit.matched_rule_ids == []
        assert audit.matched_rule_ids is not None
        assert isinstance(audit.matched_rule_ids, list)

    def test_bundle_identity_absent_agrees_for_not_applicable(self) -> None:
        trace = _completed_not_applicable_trace()
        assert trace.bundle_id is None
        assert trace.bundle_version is None
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        audit = assemble_audit_evidence(
            request=_request_for_trace(trace),
            trace=trace,
            evidence_id="ev-bundle-absent",
            recorded_at=_RECORDED_AT,
        )
        assert response.bundle_id is None
        assert response.bundle_version is None
        assert audit.bundle_id is None
        assert audit.bundle_version is None

    def test_bundle_identity_present_agrees_for_allow(self) -> None:
        trace = _completed_allow_trace()
        assert trace.bundle_id is not None
        assert trace.bundle_version is not None
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        audit = assemble_audit_evidence(
            request=_request_for_trace(trace),
            trace=trace,
            evidence_id="ev-bundle-present",
            recorded_at=_RECORDED_AT,
        )
        assert response.bundle_id == audit.bundle_id == trace.bundle_id
        assert response.bundle_version == audit.bundle_version == trace.bundle_version


# ══════════════════════════════════════════════════════════════════════════
# Serialization agreement
# ══════════════════════════════════════════════════════════════════════════


class _ResponseEnvelope(BaseModel):
    """Test-local wrapper model, used only to prove nested embedded-trace
    serialization survives when the response is itself nested inside a
    parent model's own `model_dump`/`model_dump_json` — mirroring how a
    real caller (e.g. a future gateway envelope) might nest this response."""

    model_config = ConfigDict(frozen=True)

    response: OperationAwareDecisionResponse


_SHARED_SCALAR_FIELDS = (
    "request_id",
    "correlation_id",
    "evaluation_status",
    "outcome",
    "failure_reason",
    "bundle_id",
    "bundle_version",
    "trace_id",
    "reason_code",
    "explanation",
)


class TestSerializationAgreement:
    @pytest.mark.parametrize("scenario_name", ["completed_allow", "failed_policy_validation"])
    def test_json_mode_agreement(self, scenario_name: str) -> None:
        trace = _SCENARIO_TRACE_BUILDERS[scenario_name]()
        request = _request_for_trace(trace)
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        audit = assemble_audit_evidence(
            request=request,
            trace=trace,
            evidence_id=f"ev-serialization-{scenario_name}",
            recorded_at=_RECORDED_AT,
        )
        response_dump = response.model_dump(mode="json")
        audit_dump = audit.model_dump(mode="json")
        for field_name in _SHARED_SCALAR_FIELDS:
            assert response_dump[field_name] == audit_dump[field_name], (
                f"{field_name} disagrees after model_dump(mode='json'): "
                f"response={response_dump[field_name]!r} audit={audit_dump[field_name]!r}"
            )

    @pytest.mark.parametrize("scenario_name", ["completed_allow", "failed_policy_validation"])
    def test_exclude_none_preserves_required_nullable_keys(self, scenario_name: str) -> None:
        trace = _SCENARIO_TRACE_BUILDERS[scenario_name]()
        request = _request_for_trace(trace)
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        audit = assemble_audit_evidence(
            request=request,
            trace=trace,
            evidence_id=f"ev-exclude-none-{scenario_name}",
            recorded_at=_RECORDED_AT,
        )
        response_dump = response.model_dump(mode="json", exclude_none=True)
        audit_dump = audit.model_dump(mode="json", exclude_none=True)
        # outcome/failure_reason are required-nullable on both models: the
        # key must survive exclude_none even when the value is None.
        assert "outcome" in response_dump
        assert "failure_reason" in response_dump
        assert "outcome" in audit_dump
        assert "failure_reason" in audit_dump
        assert response_dump["outcome"] == audit_dump["outcome"]
        assert response_dump["failure_reason"] == audit_dump["failure_reason"]

    def test_model_dump_json_agreement(self) -> None:
        trace = _completed_allow_trace()
        request = _request_for_trace(trace)
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=False
        )
        audit = assemble_audit_evidence(
            request=request, trace=trace, evidence_id="ev-model-dump-json", recorded_at=_RECORDED_AT
        )
        response_parsed = json.loads(response.model_dump_json())
        audit_parsed = json.loads(audit.model_dump_json())
        for field_name in _SHARED_SCALAR_FIELDS:
            assert response_parsed[field_name] == audit_parsed[field_name], (
                f"{field_name} disagrees after model_dump_json(): "
                f"response={response_parsed[field_name]!r} audit={audit_parsed[field_name]!r}"
            )

    def test_embedded_nested_serialization_preserves_agreement(self) -> None:
        trace = _completed_allow_trace()
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=True
        )
        envelope = _ResponseEnvelope(response=response)
        envelope_dump = envelope.model_dump(mode="json")
        nested_trace_dump = envelope_dump["response"]["evaluation_trace"]
        assert nested_trace_dump is not None
        assert nested_trace_dump["trace_id"] == envelope_dump["response"]["trace_id"]
        assert nested_trace_dump["request_id"] == envelope_dump["response"]["request_id"]
        assert nested_trace_dump["reason_code"] == envelope_dump["response"]["reason_code"]
        assert nested_trace_dump["explanation"] == envelope_dump["response"]["explanation"]
        # Top-level agreement fields are unaffected by nesting.
        assert envelope_dump["response"]["request_id"] == trace.request_id
        assert envelope_dump["response"]["trace_id"] == trace.trace_id

    def test_embedded_nested_serialization_with_exclude_none_still_shows_required_nullable(
        self,
    ) -> None:
        trace = _failed_trace()
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=True
        )
        envelope = _ResponseEnvelope(response=response)
        envelope_dump = envelope.model_dump(mode="json", exclude_none=True)
        nested_trace_dump = envelope_dump["response"]["evaluation_trace"]
        # EvaluationTrace's own required-nullable fields (outcome,
        # bundle_applicability) must survive exclude_none even nested two
        # levels deep inside this envelope.
        assert "outcome" in nested_trace_dump
        assert nested_trace_dump["outcome"] is None
        assert "bundle_applicability" in nested_trace_dump
        assert nested_trace_dump["bundle_applicability"] is None
        assert "outcome" in envelope_dump["response"]
        assert envelope_dump["response"]["outcome"] is None
        assert "failure_reason" in envelope_dump["response"]


# ══════════════════════════════════════════════════════════════════════════
# Determinism and immutability
# ══════════════════════════════════════════════════════════════════════════


class TestDeterminismAndImmutability:
    def test_repeat_assembly_is_deterministic(self) -> None:
        trace = _completed_allow_trace()
        request = _request_for_trace(trace)
        first_response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=True
        )
        second_response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=True
        )
        assert first_response == second_response

        first_audit = assemble_audit_evidence(
            request=request, trace=trace, evidence_id="ev-det-1", recorded_at=_RECORDED_AT
        )
        second_audit = assemble_audit_evidence(
            request=request, trace=trace, evidence_id="ev-det-1", recorded_at=_RECORDED_AT
        )
        assert first_audit == second_audit

    def test_agreement_result_is_identical_across_repeat_assembly(self) -> None:
        trace = _completed_allow_trace()
        request = _request_for_trace(trace)
        for _ in range(2):
            response = assemble_operation_aware_decision_response(
                trace=trace, embed_evaluation_trace=False
            )
            audit = assemble_audit_evidence(
                request=request, trace=trace, evidence_id="ev-det-2", recorded_at=_RECORDED_AT
            )
            # Must not raise on either pass.
            _assert_complete_artifact_agreement(response, trace, audit, request)

    def test_request_is_not_mutated_by_assembly_or_by_agreement_assertions(self) -> None:
        trace = _completed_allow_trace()
        request = _request_for_trace(
            trace,
            identity_evidence_reference=_identity_evidence_reference(),
            adapter_evidence_reference=_adapter_evidence_reference(),
        )
        before = request.model_dump(mode="json")
        audit = assemble_audit_evidence(
            request=request, trace=trace, evidence_id="ev-immutable-req", recorded_at=_RECORDED_AT
        )
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=True
        )
        _assert_complete_artifact_agreement(response, trace, audit, request)
        after = request.model_dump(mode="json")
        assert before == after

    def test_trace_is_not_mutated_by_assembly_or_by_agreement_assertions(self) -> None:
        trace = _completed_allow_trace()
        request = _request_for_trace(trace)
        before = trace.model_dump(mode="json")
        audit = assemble_audit_evidence(
            request=request, trace=trace, evidence_id="ev-immutable-trace", recorded_at=_RECORDED_AT
        )
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=True
        )
        _assert_complete_artifact_agreement(response, trace, audit, request)
        after = trace.model_dump(mode="json")
        assert before == after

    def test_response_and_audit_are_not_mutated_by_agreement_assertions(self) -> None:
        trace = _completed_allow_trace()
        request = _request_for_trace(trace)
        response = assemble_operation_aware_decision_response(
            trace=trace, embed_evaluation_trace=True
        )
        audit = assemble_audit_evidence(
            request=request,
            trace=trace,
            evidence_id="ev-immutable-artifacts",
            recorded_at=_RECORDED_AT,
        )
        response_before = response.model_dump(mode="json")
        audit_before = audit.model_dump(mode="json")
        _assert_complete_artifact_agreement(response, trace, audit, request)
        assert response.model_dump(mode="json") == response_before
        assert audit.model_dump(mode="json") == audit_before

    def test_nested_rule_evidence_is_not_mutated(self) -> None:
        trace = _completed_explicit_deny_trace()
        request = _request_for_trace(trace)
        before = [entry.model_dump(mode="json") for entry in trace.rule_evidence]
        audit = assemble_audit_evidence(
            request=request,
            trace=trace,
            evidence_id="ev-immutable-rule-evidence",
            recorded_at=_RECORDED_AT,
        )
        _assert_matched_rule_agreement(audit, trace)
        after = [entry.model_dump(mode="json") for entry in trace.rule_evidence]
        assert before == after


# ══════════════════════════════════════════════════════════════════════════
# Negative mutation matrix
# ══════════════════════════════════════════════════════════════════════════


def _baseline_allow_artifacts() -> tuple[
    OperationAwareDecisionResponse, EvaluationTrace, AuditEvidence, OperationAwareDecisionRequest
]:
    trace = _completed_allow_trace()
    request = _request_for_trace(trace)
    response = assemble_operation_aware_decision_response(trace=trace, embed_evaluation_trace=True)
    audit = assemble_audit_evidence(
        request=request, trace=trace, evidence_id="ev-mutation-baseline", recorded_at=_RECORDED_AT
    )
    return response, trace, audit, request


def _mutation_case_1_response_request_id() -> None:
    response, trace, _audit, _request = _baseline_allow_artifacts()
    mutated = response.model_copy(update={"request_id": "req-mutated-different"})
    with pytest.raises(AssertionError, match="request_id"):
        _assert_response_trace_agree(mutated, trace)


def _mutation_case_2_audit_request_id() -> None:
    _response, trace, audit, _request = _baseline_allow_artifacts()
    mutated = audit.model_copy(update={"request_id": "req-mutated-different"})
    with pytest.raises(AssertionError, match="request_id"):
        _assert_audit_trace_agree(mutated, trace)


def _mutation_case_3_response_correlation_id() -> None:
    response, trace, _audit, _request = _baseline_allow_artifacts()
    mutated = response.model_copy(update={"correlation_id": "corr-mutated-different"})
    with pytest.raises(AssertionError, match="correlation_id"):
        _assert_response_trace_agree(mutated, trace)


def _mutation_case_4_audit_correlation_id() -> None:
    _response, trace, audit, _request = _baseline_allow_artifacts()
    mutated = audit.model_copy(update={"correlation_id": "corr-mutated-different"})
    with pytest.raises(AssertionError, match="correlation_id"):
        _assert_audit_trace_agree(mutated, trace)


def _mutation_case_5_response_evaluation_status() -> None:
    response, trace, _audit, _request = _baseline_allow_artifacts()
    mutated = response.model_copy(
        update={"evaluation_status": OperationAwareEvaluationStatus.FAILED}
    )
    with pytest.raises(AssertionError, match="evaluation_status"):
        _assert_response_trace_agree(mutated, trace)


def _mutation_case_6_audit_evaluation_status() -> None:
    _response, trace, audit, _request = _baseline_allow_artifacts()
    mutated = audit.model_copy(update={"evaluation_status": OperationAwareEvaluationStatus.FAILED})
    with pytest.raises(AssertionError, match="evaluation_status"):
        _assert_audit_trace_agree(mutated, trace)


def _mutation_case_7_response_outcome() -> None:
    response, trace, _audit, _request = _baseline_allow_artifacts()
    mutated = response.model_copy(update={"outcome": OperationAwareDecisionOutcome.DENY})
    with pytest.raises(AssertionError, match="outcome"):
        _assert_response_trace_agree(mutated, trace)


def _mutation_case_8_audit_outcome() -> None:
    _response, trace, audit, _request = _baseline_allow_artifacts()
    mutated = audit.model_copy(update={"outcome": OperationAwareDecisionOutcome.DENY})
    with pytest.raises(AssertionError, match="outcome"):
        _assert_audit_trace_agree(mutated, trace)


def _mutation_case_9_response_failure_reason() -> None:
    response, trace, _audit, _request = _baseline_allow_artifacts()
    mutated = response.model_copy(
        update={"failure_reason": OperationAwareFailureReason.INTERNAL_EVALUATION_ERROR}
    )
    with pytest.raises(AssertionError, match="failure_reason"):
        _assert_response_trace_agree(mutated, trace)


def _mutation_case_10_audit_failure_reason() -> None:
    _response, trace, audit, _request = _baseline_allow_artifacts()
    mutated = audit.model_copy(
        update={"failure_reason": OperationAwareFailureReason.INTERNAL_EVALUATION_ERROR}
    )
    with pytest.raises(AssertionError, match="failure_reason"):
        _assert_audit_trace_agree(mutated, trace)


def _mutation_case_11_response_bundle_id() -> None:
    response, trace, _audit, _request = _baseline_allow_artifacts()
    mutated = response.model_copy(update={"bundle_id": "bundle-mutated-different"})
    with pytest.raises(AssertionError, match="bundle_id"):
        _assert_response_trace_agree(mutated, trace)


def _mutation_case_12_audit_bundle_id() -> None:
    _response, trace, audit, _request = _baseline_allow_artifacts()
    mutated = audit.model_copy(update={"bundle_id": "bundle-mutated-different"})
    with pytest.raises(AssertionError, match="bundle_id"):
        _assert_audit_trace_agree(mutated, trace)


def _mutation_case_13_response_bundle_version() -> None:
    response, trace, _audit, _request = _baseline_allow_artifacts()
    mutated = response.model_copy(update={"bundle_version": "9.9.9"})
    with pytest.raises(AssertionError, match="bundle_version"):
        _assert_response_trace_agree(mutated, trace)


def _mutation_case_14_audit_bundle_version() -> None:
    _response, trace, audit, _request = _baseline_allow_artifacts()
    mutated = audit.model_copy(update={"bundle_version": "9.9.9"})
    with pytest.raises(AssertionError, match="bundle_version"):
        _assert_audit_trace_agree(mutated, trace)


def _mutation_case_15_response_trace_id() -> None:
    response, trace, _audit, _request = _baseline_allow_artifacts()
    mutated = response.model_copy(update={"trace_id": "trace-mutated-different"})
    with pytest.raises(AssertionError, match="trace_id"):
        _assert_response_trace_agree(mutated, trace)


def _mutation_case_16_audit_trace_id() -> None:
    _response, trace, audit, _request = _baseline_allow_artifacts()
    mutated = audit.model_copy(update={"trace_id": "trace-mutated-different"})
    with pytest.raises(AssertionError, match="trace_id"):
        _assert_audit_trace_agree(mutated, trace)


def _mutation_case_17_response_reason_code() -> None:
    response, trace, _audit, _request = _baseline_allow_artifacts()
    mutated = response.model_copy(update={"reason_code": ReasonCode("different_reason_code")})
    with pytest.raises(AssertionError, match="reason_code"):
        _assert_response_trace_agree(mutated, trace)


def _mutation_case_18_audit_reason_code() -> None:
    _response, trace, audit, _request = _baseline_allow_artifacts()
    mutated = audit.model_copy(update={"reason_code": ReasonCode("different_reason_code")})
    with pytest.raises(AssertionError, match="reason_code"):
        _assert_audit_trace_agree(mutated, trace)


def _mutation_case_19_response_explanation() -> None:
    response, trace, _audit, _request = _baseline_allow_artifacts()
    mutated = response.model_copy(update={"explanation": "A materially different explanation."})
    with pytest.raises(AssertionError, match="explanation"):
        _assert_response_trace_agree(mutated, trace)


def _mutation_case_20_audit_explanation() -> None:
    _response, trace, audit, _request = _baseline_allow_artifacts()
    mutated = audit.model_copy(update={"explanation": "A materially different explanation."})
    with pytest.raises(AssertionError, match="explanation"):
        _assert_audit_trace_agree(mutated, trace)


def _mutation_case_21_embedded_trace_differs() -> None:
    response, trace, _audit, _request = _baseline_allow_artifacts()
    mutated_trace = trace.model_copy(update={"explanation": "A different embedded explanation."})
    mutated_response = response.model_copy(update={"evaluation_trace": mutated_trace})
    with pytest.raises(AssertionError, match="embedded evaluation_trace"):
        _assert_response_trace_agree(mutated_response, trace)


def _mutation_case_22_matched_rule_content_differs() -> None:
    _response, trace, audit, _request = _baseline_allow_artifacts()
    mutated = audit.model_copy(update={"matched_rule_ids": ["totally-different-rule"]})
    with pytest.raises(AssertionError, match="matched_rule_ids"):
        _assert_matched_rule_agreement(mutated, trace)


def _mutation_case_23_matched_rule_order_differs() -> None:
    trace = _completed_explicit_deny_trace()
    audit = assemble_audit_evidence(
        request=_request_for_trace(trace),
        trace=trace,
        evidence_id="ev-mutation-order",
        recorded_at=_RECORDED_AT,
    )
    mutated = audit.model_copy(update={"matched_rule_ids": list(reversed(audit.matched_rule_ids))})
    with pytest.raises(AssertionError, match="matched_rule_ids"):
        _assert_matched_rule_agreement(mutated, trace)


def _mutation_case_24_optional_presence_differs() -> None:
    response, trace, audit, _request = _baseline_allow_artifacts()
    mutated_audit = audit.model_copy(update={"reason_code": None})
    with pytest.raises(AssertionError, match="reason_code"):
        _assert_response_audit_agree(response, mutated_audit)


_MUTATION_CASES = {
    "01_response_request_id": _mutation_case_1_response_request_id,
    "02_audit_request_id": _mutation_case_2_audit_request_id,
    "03_response_correlation_id": _mutation_case_3_response_correlation_id,
    "04_audit_correlation_id": _mutation_case_4_audit_correlation_id,
    "05_response_evaluation_status": _mutation_case_5_response_evaluation_status,
    "06_audit_evaluation_status": _mutation_case_6_audit_evaluation_status,
    "07_response_outcome": _mutation_case_7_response_outcome,
    "08_audit_outcome": _mutation_case_8_audit_outcome,
    "09_response_failure_reason": _mutation_case_9_response_failure_reason,
    "10_audit_failure_reason": _mutation_case_10_audit_failure_reason,
    "11_response_bundle_id": _mutation_case_11_response_bundle_id,
    "12_audit_bundle_id": _mutation_case_12_audit_bundle_id,
    "13_response_bundle_version": _mutation_case_13_response_bundle_version,
    "14_audit_bundle_version": _mutation_case_14_audit_bundle_version,
    "15_response_trace_id": _mutation_case_15_response_trace_id,
    "16_audit_trace_id": _mutation_case_16_audit_trace_id,
    "17_response_reason_code": _mutation_case_17_response_reason_code,
    "18_audit_reason_code": _mutation_case_18_audit_reason_code,
    "19_response_explanation": _mutation_case_19_response_explanation,
    "20_audit_explanation": _mutation_case_20_audit_explanation,
    "21_embedded_trace_differs": _mutation_case_21_embedded_trace_differs,
    "22_matched_rule_content_differs": _mutation_case_22_matched_rule_content_differs,
    "23_matched_rule_order_differs": _mutation_case_23_matched_rule_order_differs,
    "24_optional_presence_differs": _mutation_case_24_optional_presence_differs,
}


class TestNegativeMutationMatrix:
    def test_exactly_twenty_four_mutation_cases_are_defined(self) -> None:
        assert len(_MUTATION_CASES) == 24

    @pytest.mark.parametrize("case_name", list(_MUTATION_CASES))
    def test_mutation_case_is_detected(self, case_name: str) -> None:
        _MUTATION_CASES[case_name]()

    def test_original_artifacts_are_unaffected_by_mutation_helpers(self) -> None:
        """`model_copy` never mutates the original — every mutation case
        above operates on a copy, never the baseline artifact itself."""
        response, trace, audit, _request = _baseline_allow_artifacts()
        response_before = response.model_dump(mode="json")
        trace_before = trace.model_dump(mode="json")
        audit_before = audit.model_dump(mode="json")
        for case in _MUTATION_CASES.values():
            case()
        assert response.model_dump(mode="json") == response_before
        assert trace.model_dump(mode="json") == trace_before
        assert audit.model_dump(mode="json") == audit_before


# ══════════════════════════════════════════════════════════════════════════
# No engine, no gateway artifact, no fixture-runtime dependency
# ══════════════════════════════════════════════════════════════════════════


def test_module_does_not_import_yaml_or_snapshot_helpers() -> None:
    """Mechanical proof that this module never loads the vendored v0.2.1
    compatibility fixtures at runtime — style mirrors
    `test_engine_canonical_shapes.py::test_module_does_not_import_yaml_or_snapshot_helpers`."""
    source = inspect.getsource(sys.modules[__name__])
    tree = ast.parse(source)
    imported_modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported_modules.append(node.module)
        elif isinstance(node, ast.Import):
            imported_modules.extend(alias.name for alias in node.names)

    forbidden_prefixes = (
        "yaml",
        "tests.helpers.basis_schemas_snapshot",
        "tests.helpers.operation_aware_contracts",
    )
    violations = [
        module
        for module in imported_modules
        if any(module == prefix or module.startswith(prefix + ".") for prefix in forbidden_prefixes)
    ]
    assert violations == [], (
        f"test_artifact_agreement.py must not import a fixture-loading module at runtime; "
        f"found: {violations}"
    )


def test_module_does_not_invoke_engine_policy_or_gateway_artifacts() -> None:
    """No `OperationAwareEvaluationEngine`, no `basis_core.policy`, no
    `basis_core.enforcement`, no `GatewayAuditEvent` — this module proves
    assembler-output agreement only, never engine orchestration or
    gateway-owned enforcement facts."""
    source = inspect.getsource(sys.modules[__name__])
    tree = ast.parse(source)

    imported_names: set[str] = set()
    imported_modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imported_names.update(alias.name for alias in node.names)
            if node.module:
                imported_modules.append(node.module)
        elif isinstance(node, ast.Import):
            imported_names.update(alias.name for alias in node.names)
            imported_modules.extend(alias.name for alias in node.names)

    assert "OperationAwareEvaluationEngine" not in imported_names
    assert "GatewayAuditEvent" not in imported_names
    assert not any(m == "basis_core.evaluation.operation_aware.engine" for m in imported_modules)
    assert not any(m.startswith("basis_core.policy") for m in imported_modules)
    assert not any(m.startswith("basis_core.enforcement") for m in imported_modules)
    assert not any(m.startswith("basis_core.adapters") for m in imported_modules)


def test_module_defines_no_production_agreement_validator() -> None:
    """This module's own assertion helpers are test-local only — it defines
    no production-shaped agreement API (`validate_artifact_agreement`,
    `ArtifactAgreementValidator`, `reconcile_artifacts`,
    `normalize_artifacts`, `synchronize_response_and_audit`, and similar)."""
    source = inspect.getsource(sys.modules[__name__])
    tree = ast.parse(source)
    forbidden_names = {
        "validate_artifact_agreement",
        "assert_artifacts_consistent",
        "ArtifactAgreementValidator",
        "reconcile_artifacts",
        "normalize_artifacts",
        "synchronize_response_and_audit",
    }
    defined_names = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    }
    assert defined_names.isdisjoint(forbidden_names)
