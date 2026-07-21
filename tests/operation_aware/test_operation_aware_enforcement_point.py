"""
tests/operation_aware/test_operation_aware_enforcement_point.py — tests for
`basis_core.enforcement.operation_aware` (Milestone 11, PR 34 of
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`:
"OperationAwareEnforcementPoint implementation"), proving the full
`docs/adr/ADR-0006-operation-aware-enforcement-point.md` PR 34 test
contract (22 items).

This file proves *enforcement-boundary composition and fail-closed
containment* — that `OperationAwareEnforcementPoint.evaluate()` correctly
sequences `OperationAwareEvaluationEngine.evaluate()`,
`assemble_operation_aware_decision_response()`, and
`assemble_audit_evidence()`; correctly derives `EnforcementDisposition`;
and never raises. It does not retest bundle applicability, selector
matching, condition-operator behavior, effect aggregation, or response/
audit-evidence field-mapping semantics — `test_evaluation_engine.py`,
`test_response_assembly.py`, and their siblings already own those. Where a
real, valid `EvaluationTrace` is needed but is not reachable through
`OperationAwareEvaluationEngine`'s own typed entry point (`invalid_request`,
`unsupported_schema_version`, `invalid_policy_bundle` — see that module's
own docstring), a small stub engine returns an already-built, real,
validated `EvaluationTrace` (via `assemble_evaluation_trace`, the same
production helper the real engine itself uses) rather than reimplementing
any evaluation semantics.
"""

from __future__ import annotations

import ast
import dataclasses
from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

import basis_core
import basis_core.enforcement as enforcement_package
from basis_core.audit.operation_aware.audit_evidence import AuditEvidence
from basis_core.audit.operation_aware.evaluation_trace import (
    EvaluationStatus,
    EvaluationTrace,
    TraceFailureReason,
)
from basis_core.decisions.operation_aware import (
    OperationAwareDecisionOutcome,
    OperationAwareDecisionRequest,
    OperationAwareEvaluationStatus,
    OperationAwareFailureReason,
)
from basis_core.enforcement import operation_aware
from basis_core.enforcement.enforcement import EnforcementPoint
from basis_core.enforcement.operation_aware import (
    EnforcementDisposition,
    OperationAwareEnforcementPoint,
    OperationAwareEnforcementResult,
)
from basis_core.evaluation.operation_aware.engine import OperationAwareEvaluationEngine
from basis_core.evaluation.operation_aware.response import OperationAwareDecisionResponse
from basis_core.evaluation.operation_aware.response_assembly import (
    EvaluationArtifactIdentityMismatchError,
)
from basis_core.evaluation.operation_aware.trace_assembly import assemble_evaluation_trace
from basis_core.policy.operation_aware.bundle import PolicyBundle

SRC_ROOT = Path(__file__).parent.parent.parent / "src" / "basis_core"
MODULE_PATH = SRC_ROOT / "enforcement" / "operation_aware.py"

_SUBJECT_ID = "svc-enforcement-test"
_RECORDED_AT = datetime(2026, 5, 22, 14, 30, 1, tzinfo=timezone.utc)


# ══════════════════════════════════════════════════════════════════════════
# Shared construction helpers — mirrors tests/operation_aware/
# test_evaluation_engine.py's own helpers; not reimplemented differently.
# ══════════════════════════════════════════════════════════════════════════


def _build_request(**overrides: object) -> OperationAwareDecisionRequest:
    kwargs: dict[str, object] = {
        "request_id": "req-enforcement-fixture-0001",
        "correlation_id": "corr-enforcement-fixture-0001",
        "subject_id": _SUBJECT_ID,
        "action": "read:ahu",
    }
    kwargs.update(overrides)
    return OperationAwareDecisionRequest.model_validate(kwargs)


def _rule_dict(
    rule_id: str,
    *,
    effect: str = "allow",
    action: str = "read:ahu",
    conditions: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    rule: dict[str, object] = {"rule_id": rule_id, "effect": effect}
    if conditions is not None:
        rule["conditions"] = conditions
    else:
        rule["match"] = {"actions": [action]}
    return rule


def _build_bundle(
    rules: list[dict[str, object]] | None = None,
    *,
    bundle_id: str = "bundle-enforcement-fixture",
    scope: dict[str, object] | None = None,
) -> PolicyBundle:
    kwargs: dict[str, object] = {
        "bundle_id": bundle_id,
        "bundle_version": "1.0.0",
        "schema_version": "0.2.0",
        "policy_owner": "test-owner",
        "rules": rules if rules is not None else [_rule_dict("rule-1")],
    }
    if scope is not None:
        kwargs["scope"] = scope
    return PolicyBundle.model_validate(kwargs)


def _error_condition(condition_id: str) -> dict[str, object]:
    """Deterministically evaluates to an ERROR: `future_operator` is
    structurally valid but unimplemented — matching the convention every
    other operation-aware test file uses."""
    return {
        "condition_id": condition_id,
        "field_path": "subject_id",
        "operator": "future_operator",
        "expected_value": "irrelevant",
    }


def _duplicate_rule_id_bundle() -> PolicyBundle:
    """A `SemanticPolicyValidationError` (`DuplicateRuleIdError`) case —
    reachable through the real engine's typed entry point — mapped to
    `POLICY_VALIDATION_FAILURE`. See `test_evaluation_engine.py`'s own
    identical helper/docstring."""
    return _build_bundle(
        rules=[
            _rule_dict("dup-rule", effect="allow", action="read:ahu"),
            _rule_dict("dup-rule", effect="deny", action="write:ahu"),
        ]
    )


def _failed_trace(
    *,
    trace_id: str,
    request: OperationAwareDecisionRequest,
    failure_reason: TraceFailureReason,
) -> EvaluationTrace:
    """Build a real, validated, failed `EvaluationTrace` via the same
    production `assemble_evaluation_trace` helper the real engine uses
    internally — for the three `OperationAwareFailureReason` categories the
    real engine's typed entry point cannot itself reach
    (`invalid_request`/`unsupported_schema_version`/`invalid_policy_bundle`
    — see `engine.py`'s own docstring)."""
    return assemble_evaluation_trace(
        (),
        trace_id=trace_id,
        request_id=request.request_id,
        correlation_id=request.correlation_id,
        evaluation_status=EvaluationStatus.FAILED,
        outcome=None,
        bundle_applicability=None,
        failure_reason=failure_reason,
        reason_code=None,
        explanation=None,
    )


class _StubEngine:
    """A stub replacing `OperationAwareEvaluationEngine` — same keyword-only
    `evaluate(*, request, bundle, trace_id)` signature, returning an
    already-built, real, validated `EvaluationTrace` supplied at
    construction. Used only to reach failure categories (or identity
    mismatches) the real engine's typed entry point cannot itself produce;
    it implements no evaluation semantics of its own."""

    def __init__(self, trace: EvaluationTrace) -> None:
        self._trace = trace

    def evaluate(
        self, *, request: OperationAwareDecisionRequest, bundle: PolicyBundle, trace_id: str
    ) -> EvaluationTrace:
        return self._trace


class _RaisingEngine:
    """A stub engine that raises an unexpected exception — for exercising
    ADR-0006 Decision 9's unexpected-exception containment at the engine
    invocation stage."""

    def evaluate(
        self, *, request: OperationAwareDecisionRequest, bundle: PolicyBundle, trace_id: str
    ) -> EvaluationTrace:
        raise RuntimeError("engine internal wiring defect")


# ══════════════════════════════════════════════════════════════════════════
# 1. Construction and type behavior
# ══════════════════════════════════════════════════════════════════════════


class TestEnforcementDisposition:
    def test_has_exactly_two_members(self) -> None:
        assert {member.value for member in EnforcementDisposition} == {"allow", "deny"}

    def test_members_are_named_allow_and_deny(self) -> None:
        assert EnforcementDisposition.ALLOW.value == "allow"
        assert EnforcementDisposition.DENY.value == "deny"


class TestOperationAwareEnforcementResult:
    def _make(self) -> OperationAwareEnforcementResult:
        engine = OperationAwareEvaluationEngine()
        response = _successful_response(engine, outcome_action="read:ahu")
        return OperationAwareEnforcementResult(
            response=response,
            audit_evidence=None,
            disposition=EnforcementDisposition.ALLOW,
        )

    def test_is_immutable(self) -> None:
        result = self._make()
        with pytest.raises(dataclasses.FrozenInstanceError):
            result.disposition = EnforcementDisposition.DENY  # type: ignore[misc]

    def test_rejects_undeclared_fields_at_construction(self) -> None:
        with pytest.raises(TypeError):
            OperationAwareEnforcementResult(  # type: ignore[call-arg]
                response=self._make().response,
                audit_evidence=None,
                disposition=EnforcementDisposition.ALLOW,
                extra_field="not allowed",
            )

    def test_rejects_undeclared_attribute_assignment(self) -> None:
        """`frozen=True, slots=True` rejects assignment of any attribute —
        declared or not — before an undeclared name could ever be stored.
        On CPython 3.10/3.12 this raises one of `FrozenInstanceError`,
        `AttributeError`, or `TypeError` depending on interpreter version;
        this test asserts rejection, not a single specific exception type."""
        result = self._make()
        with pytest.raises((AttributeError, TypeError, dataclasses.FrozenInstanceError)):
            result.extra_field = "nope"  # type: ignore[attr-defined]

    def test_carries_response_audit_evidence_and_disposition(self) -> None:
        result = self._make()
        assert isinstance(result.response, OperationAwareDecisionResponse)
        assert result.audit_evidence is None
        assert result.disposition is EnforcementDisposition.ALLOW


class TestConstruction:
    def test_stores_engine_and_bundle_without_transformation(self) -> None:
        engine = OperationAwareEvaluationEngine()
        bundle = _build_bundle()
        ep = OperationAwareEnforcementPoint(engine=engine, bundle=bundle)
        assert ep._engine is engine
        assert ep._bundle is bundle

    def test_is_not_a_subclass_of_v01_enforcement_point(self) -> None:
        assert not issubclass(OperationAwareEnforcementPoint, EnforcementPoint)
        assert not issubclass(EnforcementPoint, OperationAwareEnforcementPoint)


# ══════════════════════════════════════════════════════════════════════════
# Helper: run a real engine + bundle through the enforcement point
# ══════════════════════════════════════════════════════════════════════════


def _successful_response(
    engine: OperationAwareEvaluationEngine, *, outcome_action: str
) -> OperationAwareDecisionResponse:
    bundle = _build_bundle(rules=[_rule_dict("rule-1", effect="allow", action=outcome_action)])
    ep = OperationAwareEnforcementPoint(engine=engine, bundle=bundle)
    result = ep.evaluate(
        request=_build_request(action=outcome_action),
        trace_id="trace-fixture-1",
        evidence_id="evidence-fixture-1",
        recorded_at=_RECORDED_AT,
    )
    return result.response


# ══════════════════════════════════════════════════════════════════════════
# 2. Successful evaluation paths
# ══════════════════════════════════════════════════════════════════════════


class TestSuccessfulAllow:
    def _evaluate(self) -> OperationAwareEnforcementResult:
        bundle = _build_bundle(rules=[_rule_dict("allow-rule", effect="allow", action="read:ahu")])
        ep = OperationAwareEnforcementPoint(engine=OperationAwareEvaluationEngine(), bundle=bundle)
        return ep.evaluate(
            request=_build_request(action="read:ahu"),
            trace_id="trace-allow-1",
            evidence_id="evidence-allow-1",
            recorded_at=_RECORDED_AT,
        )

    def test_outcome_is_allow(self) -> None:
        result = self._evaluate()
        assert result.response.evaluation_status is OperationAwareEvaluationStatus.COMPLETED
        assert result.response.outcome is OperationAwareDecisionOutcome.ALLOW

    def test_audit_evidence_is_returned(self) -> None:
        result = self._evaluate()
        assert isinstance(result.audit_evidence, AuditEvidence)
        assert result.audit_evidence.outcome is OperationAwareDecisionOutcome.ALLOW

    def test_disposition_is_allow(self) -> None:
        result = self._evaluate()
        assert result.disposition is EnforcementDisposition.ALLOW


class TestSuccessfulExplicitDeny:
    def _evaluate(self) -> OperationAwareEnforcementResult:
        bundle = _build_bundle(
            rules=[
                _rule_dict("allow-rule", effect="allow", action="read:ahu"),
                _rule_dict("deny-rule", effect="deny", action="read:ahu"),
            ]
        )
        ep = OperationAwareEnforcementPoint(engine=OperationAwareEvaluationEngine(), bundle=bundle)
        return ep.evaluate(
            request=_build_request(action="read:ahu"),
            trace_id="trace-deny-1",
            evidence_id="evidence-deny-1",
            recorded_at=_RECORDED_AT,
        )

    def test_outcome_is_deny(self) -> None:
        result = self._evaluate()
        assert result.response.outcome is OperationAwareDecisionOutcome.DENY

    def test_audit_evidence_is_returned(self) -> None:
        result = self._evaluate()
        assert isinstance(result.audit_evidence, AuditEvidence)

    def test_disposition_is_deny(self) -> None:
        result = self._evaluate()
        assert result.disposition is EnforcementDisposition.DENY


class TestDefaultDeny:
    def _evaluate(self) -> OperationAwareEnforcementResult:
        # Applicable bundle, but its one rule matches a different action —
        # no matched allow rule → default deny (never NOT_APPLICABLE).
        bundle = _build_bundle(rules=[_rule_dict("allow-rule", effect="allow", action="write:ahu")])
        ep = OperationAwareEnforcementPoint(engine=OperationAwareEvaluationEngine(), bundle=bundle)
        return ep.evaluate(
            request=_build_request(action="read:ahu"),
            trace_id="trace-default-deny-1",
            evidence_id="evidence-default-deny-1",
            recorded_at=_RECORDED_AT,
        )

    def test_outcome_is_deny(self) -> None:
        result = self._evaluate()
        assert result.response.evaluation_status is OperationAwareEvaluationStatus.COMPLETED
        assert result.response.outcome is OperationAwareDecisionOutcome.DENY

    def test_reason_code_is_preserved(self) -> None:
        result = self._evaluate()
        assert result.response.reason_code is not None

    def test_audit_evidence_is_returned(self) -> None:
        result = self._evaluate()
        assert isinstance(result.audit_evidence, AuditEvidence)

    def test_disposition_is_deny(self) -> None:
        result = self._evaluate()
        assert result.disposition is EnforcementDisposition.DENY


class TestNotApplicable:
    def _evaluate(self) -> OperationAwareEnforcementResult:
        bundle = _build_bundle(scope={"actions": ["write:ahu"]})
        ep = OperationAwareEnforcementPoint(engine=OperationAwareEvaluationEngine(), bundle=bundle)
        return ep.evaluate(
            request=_build_request(action="read:ahu"),
            trace_id="trace-na-1",
            evidence_id="evidence-na-1",
            recorded_at=_RECORDED_AT,
        )

    def test_outcome_is_not_applicable(self) -> None:
        result = self._evaluate()
        assert result.response.evaluation_status is OperationAwareEvaluationStatus.COMPLETED
        assert result.response.outcome is OperationAwareDecisionOutcome.NOT_APPLICABLE

    def test_audit_evidence_is_returned(self) -> None:
        result = self._evaluate()
        assert isinstance(result.audit_evidence, AuditEvidence)
        assert result.audit_evidence.outcome is OperationAwareDecisionOutcome.NOT_APPLICABLE

    def test_disposition_is_deny(self) -> None:
        result = self._evaluate()
        assert result.disposition is EnforcementDisposition.DENY

    def test_response_is_not_rewritten_to_deny(self) -> None:
        """The disposition collapse never touches the authoritative
        response — outcome stays not_applicable, never deny."""
        result = self._evaluate()
        assert result.response.outcome is not OperationAwareDecisionOutcome.DENY


# ══════════════════════════════════════════════════════════════════════════
# 3. Governed failed evaluation paths — every OperationAwareFailureReason
# ══════════════════════════════════════════════════════════════════════════


class TestGovernedFailurePolicyValidationFailure:
    """Reachable through the real engine: a duplicate rule_id bundle."""

    def _evaluate(self) -> OperationAwareEnforcementResult:
        ep = OperationAwareEnforcementPoint(
            engine=OperationAwareEvaluationEngine(), bundle=_duplicate_rule_id_bundle()
        )
        return ep.evaluate(
            request=_build_request(),
            trace_id="trace-pvf-1",
            evidence_id="evidence-pvf-1",
            recorded_at=_RECORDED_AT,
        )

    def test_no_exception_and_failed_shape(self) -> None:
        result = self._evaluate()
        assert result.response.evaluation_status is OperationAwareEvaluationStatus.FAILED
        assert result.response.outcome is None
        assert (
            result.response.failure_reason is OperationAwareFailureReason.POLICY_VALIDATION_FAILURE
        )

    def test_audit_evidence_is_valid(self) -> None:
        result = self._evaluate()
        assert isinstance(result.audit_evidence, AuditEvidence)
        assert result.audit_evidence.evaluation_status is OperationAwareEvaluationStatus.FAILED
        assert (
            result.audit_evidence.failure_reason
            is OperationAwareFailureReason.POLICY_VALIDATION_FAILURE
        )

    def test_disposition_is_deny(self) -> None:
        assert self._evaluate().disposition is EnforcementDisposition.DENY


class TestGovernedFailureConditionEvaluationError:
    """Reachable through the real engine: a rule whose condition errors."""

    def _evaluate(self) -> OperationAwareEnforcementResult:
        bundle = _build_bundle(
            rules=[_rule_dict("err-rule", conditions=[_error_condition("cond-1")])]
        )
        ep = OperationAwareEnforcementPoint(engine=OperationAwareEvaluationEngine(), bundle=bundle)
        return ep.evaluate(
            request=_build_request(),
            trace_id="trace-cee-1",
            evidence_id="evidence-cee-1",
            recorded_at=_RECORDED_AT,
        )

    def test_no_exception_and_failed_shape(self) -> None:
        result = self._evaluate()
        assert result.response.evaluation_status is OperationAwareEvaluationStatus.FAILED
        assert result.response.outcome is None
        assert (
            result.response.failure_reason is OperationAwareFailureReason.CONDITION_EVALUATION_ERROR
        )

    def test_audit_evidence_is_valid(self) -> None:
        result = self._evaluate()
        assert isinstance(result.audit_evidence, AuditEvidence)

    def test_disposition_is_deny(self) -> None:
        assert self._evaluate().disposition is EnforcementDisposition.DENY


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
    ],
)
class TestGovernedFailureNotReachableThroughRealEngine:
    """`invalid_request`/`unsupported_schema_version`/`invalid_policy_bundle`
    are not reachable through `OperationAwareEvaluationEngine`'s own typed
    entry point (see that module's docstring). A stub engine returns an
    already-built, real, validated failed `EvaluationTrace` for each, so
    this proves the enforcement point handles every governed category
    generically, not only the two the real engine can itself produce."""

    def _evaluate(
        self,
        trace_failure_reason: TraceFailureReason,
        response_failure_reason: OperationAwareFailureReason,
    ) -> OperationAwareEnforcementResult:
        request = _build_request()
        trace = _failed_trace(
            trace_id="trace-stub-1", request=request, failure_reason=trace_failure_reason
        )
        ep = OperationAwareEnforcementPoint(
            engine=_StubEngine(trace),
            bundle=_build_bundle(),  # type: ignore[arg-type]
        )
        return ep.evaluate(
            request=request,
            trace_id="trace-stub-1",
            evidence_id="evidence-stub-1",
            recorded_at=_RECORDED_AT,
        )

    def test_no_exception_and_failed_shape(
        self,
        trace_failure_reason: TraceFailureReason,
        response_failure_reason: OperationAwareFailureReason,
    ) -> None:
        result = self._evaluate(trace_failure_reason, response_failure_reason)
        assert result.response.evaluation_status is OperationAwareEvaluationStatus.FAILED
        assert result.response.outcome is None
        assert result.response.failure_reason is response_failure_reason

    def test_audit_evidence_is_valid(
        self,
        trace_failure_reason: TraceFailureReason,
        response_failure_reason: OperationAwareFailureReason,
    ) -> None:
        result = self._evaluate(trace_failure_reason, response_failure_reason)
        assert isinstance(result.audit_evidence, AuditEvidence)
        assert result.audit_evidence.failure_reason is response_failure_reason

    def test_disposition_is_deny(
        self,
        trace_failure_reason: TraceFailureReason,
        response_failure_reason: OperationAwareFailureReason,
    ) -> None:
        result = self._evaluate(trace_failure_reason, response_failure_reason)
        assert result.disposition is EnforcementDisposition.DENY


class TestGovernedFailureInternalEvaluationErrorViaEngine:
    """The engine returning `internal_evaluation_error` directly (as
    opposed to raising) is also an *expected* evaluator failure from the
    enforcement point's perspective — distinct from the unexpected-exception
    fallback path tested separately below."""

    def _evaluate(self) -> OperationAwareEnforcementResult:
        request = _build_request()
        trace = _failed_trace(
            trace_id="trace-iee-1",
            request=request,
            failure_reason=TraceFailureReason.INTERNAL_EVALUATION_ERROR,
        )
        ep = OperationAwareEnforcementPoint(
            engine=_StubEngine(trace),
            bundle=_build_bundle(),  # type: ignore[arg-type]
        )
        return ep.evaluate(
            request=request,
            trace_id="trace-iee-1",
            evidence_id="evidence-iee-1",
            recorded_at=_RECORDED_AT,
        )

    def test_no_exception_and_failed_shape(self) -> None:
        result = self._evaluate()
        assert result.response.evaluation_status is OperationAwareEvaluationStatus.FAILED
        assert result.response.outcome is None
        assert (
            result.response.failure_reason is OperationAwareFailureReason.INTERNAL_EVALUATION_ERROR
        )

    def test_audit_evidence_is_valid(self) -> None:
        result = self._evaluate()
        assert isinstance(result.audit_evidence, AuditEvidence)

    def test_disposition_is_deny(self) -> None:
        assert self._evaluate().disposition is EnforcementDisposition.DENY


# ══════════════════════════════════════════════════════════════════════════
# 4. Unexpected exception injection
# ══════════════════════════════════════════════════════════════════════════


def _assert_internal_error_fallback(result: OperationAwareEnforcementResult) -> None:
    assert result.response.evaluation_status is OperationAwareEvaluationStatus.FAILED
    assert result.response.outcome is None
    assert result.response.failure_reason is OperationAwareFailureReason.INTERNAL_EVALUATION_ERROR
    assert result.disposition is EnforcementDisposition.DENY
    assert result.audit_evidence is None
    assert result.response.evaluation_trace is None


class TestUnexpectedEngineException:
    def test_does_not_escape_and_falls_back_safely(self) -> None:
        request = _build_request()
        ep = OperationAwareEnforcementPoint(
            engine=_RaisingEngine(),
            bundle=_build_bundle(),  # type: ignore[arg-type]
        )
        result = ep.evaluate(
            request=request,
            trace_id="trace-exc-engine",
            evidence_id="evidence-exc-engine",
            recorded_at=_RECORDED_AT,
        )
        _assert_internal_error_fallback(result)

    def test_no_exception_text_leaks_into_response(self) -> None:
        request = _build_request()
        ep = OperationAwareEnforcementPoint(
            engine=_RaisingEngine(),
            bundle=_build_bundle(),  # type: ignore[arg-type]
        )
        result = ep.evaluate(
            request=request,
            trace_id="trace-exc-engine-2",
            evidence_id="evidence-exc-engine-2",
            recorded_at=_RECORDED_AT,
        )
        dumped = result.response.model_dump_json()
        assert "engine internal wiring defect" not in dumped
        assert "RuntimeError" not in dumped
        assert "Traceback" not in dumped


class TestUnexpectedResponseAssemblyException:
    def test_does_not_escape_and_falls_back_safely(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _boom(**kwargs: object) -> OperationAwareDecisionResponse:
            raise RuntimeError("response assembly defect")

        monkeypatch.setattr(operation_aware, "assemble_operation_aware_decision_response", _boom)
        request = _build_request(action="read:ahu")
        bundle = _build_bundle(rules=[_rule_dict("allow-rule", effect="allow", action="read:ahu")])
        ep = OperationAwareEnforcementPoint(engine=OperationAwareEvaluationEngine(), bundle=bundle)
        result = ep.evaluate(
            request=request,
            trace_id="trace-exc-response",
            evidence_id="evidence-exc-response",
            recorded_at=_RECORDED_AT,
        )
        _assert_internal_error_fallback(result)


class TestUnexpectedAuditEvidenceAssemblyException:
    def test_generic_exception_does_not_escape(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _boom(**kwargs: object) -> AuditEvidence:
            raise RuntimeError("audit evidence assembly defect")

        monkeypatch.setattr(operation_aware, "assemble_audit_evidence", _boom)
        request = _build_request(action="read:ahu")
        bundle = _build_bundle(rules=[_rule_dict("allow-rule", effect="allow", action="read:ahu")])
        ep = OperationAwareEnforcementPoint(engine=OperationAwareEvaluationEngine(), bundle=bundle)
        result = ep.evaluate(
            request=request,
            trace_id="trace-exc-evidence",
            evidence_id="evidence-exc-evidence",
            recorded_at=_RECORDED_AT,
        )
        _assert_internal_error_fallback(result)

    def test_identity_mismatch_error_does_not_escape(self) -> None:
        """A real `EvaluationArtifactIdentityMismatchError`, raised
        naturally by `assemble_audit_evidence` when the trace's
        `request_id` disagrees with the request's own — a stub engine
        returns a completed, valid trace under a different request_id than
        the request supplies."""
        request = _build_request(request_id="req-real-1", correlation_id="corr-real-1")
        # NOT_APPLICABLE with empty rule evidence is a valid completed shape.
        from basis_core.audit.operation_aware.evaluation_trace import (
            TraceBundleApplicability,
            TraceOutcome,
        )

        mismatched_trace = assemble_evaluation_trace(
            (),
            trace_id="trace-mismatch-1",
            request_id="req-DIFFERENT",
            correlation_id="corr-real-1",
            evaluation_status=EvaluationStatus.COMPLETED,
            outcome=TraceOutcome.NOT_APPLICABLE,
            bundle_applicability=TraceBundleApplicability.NOT_APPLICABLE,
        )
        ep = OperationAwareEnforcementPoint(
            engine=_StubEngine(mismatched_trace),
            bundle=_build_bundle(),  # type: ignore[arg-type]
        )
        result = ep.evaluate(
            request=request,
            trace_id="trace-mismatch-1",
            evidence_id="evidence-mismatch-1",
            recorded_at=_RECORDED_AT,
        )
        _assert_internal_error_fallback(result)

    def test_identity_mismatch_error_is_the_real_governed_error_type(self) -> None:
        """Sanity check: the scenario above genuinely exercises
        `EvaluationArtifactIdentityMismatchError`, not some other failure."""
        from basis_core.audit.operation_aware.evaluation_trace import (
            TraceBundleApplicability,
            TraceOutcome,
        )
        from basis_core.evaluation.operation_aware.response_assembly import (
            assemble_audit_evidence as real_assemble_audit_evidence,
        )

        request = _build_request(request_id="req-real-2", correlation_id="corr-real-2")
        mismatched_trace = assemble_evaluation_trace(
            (),
            trace_id="trace-mismatch-2",
            request_id="req-DIFFERENT-2",
            correlation_id="corr-real-2",
            evaluation_status=EvaluationStatus.COMPLETED,
            outcome=TraceOutcome.NOT_APPLICABLE,
            bundle_applicability=TraceBundleApplicability.NOT_APPLICABLE,
        )
        with pytest.raises(EvaluationArtifactIdentityMismatchError):
            real_assemble_audit_evidence(
                request=request,
                trace=mismatched_trace,
                evidence_id="evidence-x",
                recorded_at=_RECORDED_AT,
            )


class TestUnexpectedDispositionDerivationException:
    def test_does_not_escape_and_falls_back_safely(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _boom(response: object) -> EnforcementDisposition:
            raise RuntimeError("disposition derivation defect")

        monkeypatch.setattr(operation_aware, "_derive_disposition", _boom)
        request = _build_request(action="read:ahu")
        bundle = _build_bundle(rules=[_rule_dict("allow-rule", effect="allow", action="read:ahu")])
        ep = OperationAwareEnforcementPoint(engine=OperationAwareEvaluationEngine(), bundle=bundle)
        result = ep.evaluate(
            request=request,
            trace_id="trace-exc-disposition",
            evidence_id="evidence-exc-disposition",
            recorded_at=_RECORDED_AT,
        )
        _assert_internal_error_fallback(result)


class TestCatastrophicFailureNeverFabricatesEvidence:
    def test_audit_evidence_is_none_not_contradictory(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _boom(**kwargs: object) -> OperationAwareDecisionResponse:
            raise RuntimeError("boom")

        monkeypatch.setattr(operation_aware, "assemble_operation_aware_decision_response", _boom)
        request = _build_request(action="read:ahu")
        bundle = _build_bundle(rules=[_rule_dict("allow-rule", effect="allow", action="read:ahu")])
        ep = OperationAwareEnforcementPoint(engine=OperationAwareEvaluationEngine(), bundle=bundle)
        result = ep.evaluate(
            request=request,
            trace_id="trace-no-fabrication",
            evidence_id="evidence-no-fabrication",
            recorded_at=_RECORDED_AT,
        )
        # Either a trustworthy record, or None — never a record whose facts
        # disagree with the (also-fallback) response.
        assert result.audit_evidence is None


# ══════════════════════════════════════════════════════════════════════════
# 5. Caller-supplied facts
# ══════════════════════════════════════════════════════════════════════════


class TestCallerSuppliedFacts:
    def test_trace_id_preserved_in_response_reference_only(self) -> None:
        bundle = _build_bundle(rules=[_rule_dict("allow-rule", effect="allow", action="read:ahu")])
        ep = OperationAwareEnforcementPoint(engine=OperationAwareEvaluationEngine(), bundle=bundle)
        result = ep.evaluate(
            request=_build_request(action="read:ahu"),
            trace_id="trace-caller-1",
            evidence_id="evidence-caller-1",
            recorded_at=_RECORDED_AT,
            embed_evaluation_trace=False,
        )
        assert result.response.trace_id == "trace-caller-1"
        assert result.response.evaluation_trace is None

    def test_trace_id_preserved_in_embedded_response(self) -> None:
        bundle = _build_bundle(rules=[_rule_dict("allow-rule", effect="allow", action="read:ahu")])
        ep = OperationAwareEnforcementPoint(engine=OperationAwareEvaluationEngine(), bundle=bundle)
        result = ep.evaluate(
            request=_build_request(action="read:ahu"),
            trace_id="trace-caller-2",
            evidence_id="evidence-caller-2",
            recorded_at=_RECORDED_AT,
            embed_evaluation_trace=True,
        )
        assert result.response.trace_id == "trace-caller-2"
        assert result.response.evaluation_trace is not None
        assert result.response.evaluation_trace.trace_id == "trace-caller-2"

    def test_evidence_id_preserved(self) -> None:
        bundle = _build_bundle(rules=[_rule_dict("allow-rule", effect="allow", action="read:ahu")])
        ep = OperationAwareEnforcementPoint(engine=OperationAwareEvaluationEngine(), bundle=bundle)
        result = ep.evaluate(
            request=_build_request(action="read:ahu"),
            trace_id="trace-caller-3",
            evidence_id="evidence-caller-distinctive-id",
            recorded_at=_RECORDED_AT,
        )
        assert result.audit_evidence is not None
        assert result.audit_evidence.evidence_id == "evidence-caller-distinctive-id"

    def test_recorded_at_preserved(self) -> None:
        bundle = _build_bundle(rules=[_rule_dict("allow-rule", effect="allow", action="read:ahu")])
        ep = OperationAwareEnforcementPoint(engine=OperationAwareEvaluationEngine(), bundle=bundle)
        result = ep.evaluate(
            request=_build_request(action="read:ahu"),
            trace_id="trace-caller-4",
            evidence_id="evidence-caller-4",
            recorded_at=_RECORDED_AT,
        )
        assert result.audit_evidence is not None
        assert result.audit_evidence.recorded_at == _RECORDED_AT

    def test_request_id_and_correlation_id_preserved(self) -> None:
        bundle = _build_bundle(rules=[_rule_dict("allow-rule", effect="allow", action="read:ahu")])
        ep = OperationAwareEnforcementPoint(engine=OperationAwareEvaluationEngine(), bundle=bundle)
        request = _build_request(
            action="read:ahu", request_id="req-distinctive", correlation_id="corr-distinctive"
        )
        result = ep.evaluate(
            request=request,
            trace_id="trace-caller-5",
            evidence_id="evidence-caller-5",
            recorded_at=_RECORDED_AT,
        )
        assert result.response.request_id == "req-distinctive"
        assert result.response.correlation_id == "corr-distinctive"
        assert result.audit_evidence is not None
        assert result.audit_evidence.request_id == "req-distinctive"
        assert result.audit_evidence.correlation_id == "corr-distinctive"

    def test_request_id_and_correlation_id_preserved_on_internal_error_fallback(self) -> None:
        request = _build_request(
            action="read:ahu", request_id="req-fallback", correlation_id="corr-fallback"
        )
        ep = OperationAwareEnforcementPoint(
            engine=_RaisingEngine(),
            bundle=_build_bundle(),  # type: ignore[arg-type]
        )
        result = ep.evaluate(
            request=request,
            trace_id="trace-fallback-ref",
            evidence_id="evidence-fallback",
            recorded_at=_RECORDED_AT,
        )
        assert result.response.request_id == "req-fallback"
        assert result.response.correlation_id == "corr-fallback"
        assert result.response.trace_id == "trace-fallback-ref"


# ══════════════════════════════════════════════════════════════════════════
# 6. Determinism and immutability
# ══════════════════════════════════════════════════════════════════════════


class TestDeterminism:
    def test_equal_inputs_produce_equal_results(self) -> None:
        bundle = _build_bundle(rules=[_rule_dict("allow-rule", effect="allow", action="read:ahu")])
        ep1 = OperationAwareEnforcementPoint(engine=OperationAwareEvaluationEngine(), bundle=bundle)
        ep2 = OperationAwareEnforcementPoint(engine=OperationAwareEvaluationEngine(), bundle=bundle)
        request = _build_request(action="read:ahu")

        result1 = ep1.evaluate(
            request=request,
            trace_id="trace-det-1",
            evidence_id="evidence-det-1",
            recorded_at=_RECORDED_AT,
        )
        result2 = ep2.evaluate(
            request=request,
            trace_id="trace-det-1",
            evidence_id="evidence-det-1",
            recorded_at=_RECORDED_AT,
        )
        assert result1 == result2

    def test_repeated_evaluation_on_same_instance_is_stable(self) -> None:
        bundle = _build_bundle(rules=[_rule_dict("allow-rule", effect="allow", action="read:ahu")])
        ep = OperationAwareEnforcementPoint(engine=OperationAwareEvaluationEngine(), bundle=bundle)
        request = _build_request(action="read:ahu")

        results = [
            ep.evaluate(
                request=request,
                trace_id="trace-det-2",
                evidence_id="evidence-det-2",
                recorded_at=_RECORDED_AT,
            )
            for _ in range(3)
        ]
        assert results[0] == results[1] == results[2]


class TestImmutability:
    def test_request_is_not_mutated(self) -> None:
        bundle = _build_bundle(rules=[_rule_dict("allow-rule", effect="allow", action="read:ahu")])
        ep = OperationAwareEnforcementPoint(engine=OperationAwareEvaluationEngine(), bundle=bundle)
        request = _build_request(action="read:ahu")
        ep.evaluate(
            request=request,
            trace_id="trace-immut-1",
            evidence_id="evidence-immut-1",
            recorded_at=_RECORDED_AT,
        )
        with pytest.raises(ValidationError):
            request.action = "write:ahu"  # type: ignore[misc]

    def test_bundle_is_not_mutated(self) -> None:
        bundle = _build_bundle(rules=[_rule_dict("allow-rule", effect="allow", action="read:ahu")])
        ep = OperationAwareEnforcementPoint(engine=OperationAwareEvaluationEngine(), bundle=bundle)
        ep.evaluate(
            request=_build_request(action="read:ahu"),
            trace_id="trace-immut-2",
            evidence_id="evidence-immut-2",
            recorded_at=_RECORDED_AT,
        )
        with pytest.raises(ValidationError):
            bundle.bundle_version = "9.9.9"  # type: ignore[misc]

    def test_response_is_immutable(self) -> None:
        bundle = _build_bundle(rules=[_rule_dict("allow-rule", effect="allow", action="read:ahu")])
        ep = OperationAwareEnforcementPoint(engine=OperationAwareEvaluationEngine(), bundle=bundle)
        result = ep.evaluate(
            request=_build_request(action="read:ahu"),
            trace_id="trace-immut-3",
            evidence_id="evidence-immut-3",
            recorded_at=_RECORDED_AT,
        )
        with pytest.raises(ValidationError):
            result.response.outcome = OperationAwareDecisionOutcome.DENY  # type: ignore[misc]

    def test_audit_evidence_is_immutable(self) -> None:
        bundle = _build_bundle(rules=[_rule_dict("allow-rule", effect="allow", action="read:ahu")])
        ep = OperationAwareEnforcementPoint(engine=OperationAwareEvaluationEngine(), bundle=bundle)
        result = ep.evaluate(
            request=_build_request(action="read:ahu"),
            trace_id="trace-immut-4",
            evidence_id="evidence-immut-4",
            recorded_at=_RECORDED_AT,
        )
        assert result.audit_evidence is not None
        with pytest.raises(ValidationError):
            result.audit_evidence.evidence_id = "changed"  # type: ignore[misc]

    def test_result_carrier_is_immutable(self) -> None:
        bundle = _build_bundle(rules=[_rule_dict("allow-rule", effect="allow", action="read:ahu")])
        ep = OperationAwareEnforcementPoint(engine=OperationAwareEvaluationEngine(), bundle=bundle)
        result = ep.evaluate(
            request=_build_request(action="read:ahu"),
            trace_id="trace-immut-5",
            evidence_id="evidence-immut-5",
            recorded_at=_RECORDED_AT,
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            result.disposition = EnforcementDisposition.DENY  # type: ignore[misc]


# ══════════════════════════════════════════════════════════════════════════
# 7. v0.1 coexistence and regression
# ══════════════════════════════════════════════════════════════════════════


class TestV01Coexistence:
    def test_operation_aware_enforcement_point_is_a_separate_type(self) -> None:
        assert OperationAwareEnforcementPoint is not EnforcementPoint
        assert not issubclass(OperationAwareEnforcementPoint, EnforcementPoint)
        assert not issubclass(EnforcementPoint, OperationAwareEnforcementPoint)

    def test_v01_enforcement_point_unaffected_by_new_module_import(self) -> None:
        """Importing the operation-aware module must not alter v0.1
        EnforcementPoint's own construction contract."""
        from basis_core.audit.writer import NullAuditWriter
        from basis_core.decisions.models import DecisionOutcome, DecisionRequest
        from basis_core.domain.subject import Subject
        from basis_core.policy.engine import PolicyEngine
        from basis_core.policy.rules import RolePolicyRule

        ep = EnforcementPoint(
            engine=PolicyEngine(policies=[RolePolicyRule({"write:hvac:setpoint": {"operator"}})]),
            audit_writer=NullAuditWriter(),
        )
        subject = Subject(id="u1", name="alice", roles=["operator"])
        request = DecisionRequest(
            subject_id="u1",
            subject_roles=["operator"],
            resource_id="hvac:zone-a",
            action="write:hvac:setpoint",
        )
        response = ep.evaluate(request, subject=subject)
        assert response.outcome == DecisionOutcome.ALLOW


# ══════════════════════════════════════════════════════════════════════════
# 8. Import and side-effect boundaries
# ══════════════════════════════════════════════════════════════════════════


def _module_imports() -> list[str]:
    source = MODULE_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(MODULE_PATH))
    imports: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.append(node.module)
    return imports


class TestImportBoundaries:
    def test_only_imports_legal_layers(self) -> None:
        imports = _module_imports()
        legal_prefixes = (
            "basis_core.audit",
            "basis_core.decisions",
            "basis_core.evaluation",
            "basis_core.policy",
            "basis_core.domain",
        )
        basis_core_imports = [m for m in imports if m.startswith("basis_core.")]
        illegal = [
            m for m in basis_core_imports if not any(m.startswith(p) for p in legal_prefixes)
        ]
        assert illegal == [], f"operation_aware.py imports a forbidden layer: {illegal}"

    def test_does_not_import_adapters_or_enforcement_internals(self) -> None:
        imports = _module_imports()
        assert not any(m.startswith("basis_core.adapters") for m in imports)
        assert not any(m == "basis_core.enforcement.enforcement" for m in imports)

    def test_does_not_import_forbidden_external_packages(self) -> None:
        imports = _module_imports()
        forbidden_prefixes = (
            "requests",
            "httpx",
            "urllib3",
            "sqlalchemy",
            "psycopg",
            "pymongo",
            "redis",
            "boto3",
            "azure",
            "google.cloud",
            "kubernetes",
            "fastapi",
            "flask",
            "subprocess",
        )
        violations = [
            m for m in imports if any(m == p or m.startswith(p + ".") for p in forbidden_prefixes)
        ]
        assert violations == []

    def test_source_does_not_reference_forbidden_symbols(self) -> None:
        """AST-based, not a raw substring scan — the module's own docstrings
        legitimately *discuss* `GatewayAuditEvent`/`AuditWriter` in prose
        (explaining what this module deliberately does not do); what must
        never appear is an actual reference to either name in executable
        code (an import, a call, an attribute access, or a bare name)."""
        tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"), filename=str(MODULE_PATH))
        used_names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                used_names.add(node.id)
            elif isinstance(node, ast.Attribute):
                used_names.add(node.attr)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    used_names.add(alias.asname or alias.name.split(".")[-1])
            elif isinstance(node, ast.FunctionDef):
                used_names.add(node.name)
            elif isinstance(node, ast.ClassDef):
                used_names.add(node.name)

        forbidden_names = {
            "GatewayAuditEvent",
            "AuditWriter",
            "uuid4",
            "now",
            "utcnow",
            "random",
            "subprocess",
            "requests",
            "httpx",
        }
        violations = used_names & forbidden_names
        assert violations == set(), f"forbidden symbol(s) referenced in code: {violations}"

    def test_no_audit_writer_equivalent_protocol_introduced(self) -> None:
        tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"), filename=str(MODULE_PATH))
        function_names = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
        class_names = {node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)}
        assert "write" not in function_names
        assert not any("Writer" in name for name in class_names)


# ══════════════════════════════════════════════════════════════════════════
# 9. Public export restraint
# ══════════════════════════════════════════════════════════════════════════


class TestPublicExportRestraint:
    def test_not_exported_from_basis_core(self) -> None:
        for name in (
            "OperationAwareEnforcementPoint",
            "OperationAwareEnforcementResult",
            "EnforcementDisposition",
        ):
            assert not hasattr(basis_core, name)
            assert name not in getattr(basis_core, "__all__", [])

    def test_not_exported_from_enforcement_package(self) -> None:
        for name in (
            "OperationAwareEnforcementPoint",
            "OperationAwareEnforcementResult",
            "EnforcementDisposition",
        ):
            assert not hasattr(enforcement_package, name)
            assert name not in enforcement_package.__all__

    def test_enforcement_all_is_unchanged(self) -> None:
        assert enforcement_package.__all__ == ["EnforcementPoint"]

    def test_importable_only_from_concrete_internal_module(self) -> None:
        # This import succeeding is the point: the concrete module path
        # remains available even though the package-level export does not.
        from basis_core.enforcement.operation_aware import (  # noqa: F401
            EnforcementDisposition,
            OperationAwareEnforcementPoint,
            OperationAwareEnforcementResult,
        )
