"""
tests/operation_aware/test_evaluation_engine.py — tests for
`basis_core.evaluation.operation_aware.engine.OperationAwareEvaluationEngine`
(Milestone 9, PR 27B of
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`:
"Evaluation-owned orchestration engine").

This file proves *orchestration* — stage sequencing, deterministic type
mapping, identity provenance, and short-circuit behavior — not the
semantics each invoked stage already owns and already has its own focused
test file for. It does not retest bundle applicability, selector matching,
condition-operator behavior, or effect-aggregation semantics beyond what is
needed to prove the engine composes them correctly; `test_applicability.py`,
`test_selector.py`, `test_condition_eval.py`, `test_operators.py`, and
`test_policy_aggregation.py` own those.

Policy-validation failure mapping
──────────────────────────────────
The "invalid policy" tests in this file exercise both reachable semantic
validation failures — a duplicate-`rule_id` bundle and a duplicate-
`condition_id` bundle (the latter built the same
`model_construct`-bypass way `test_policy_validation.py` builds it, since
`rule.py`'s own constructor already blocks it) — and assert the engine
reports `OperationAwareFailureReason.POLICY_VALIDATION_FAILURE`, not
`INVALID_POLICY_BUNDLE`. See `engine.py`'s own docstring, "Policy-validation
failure mapping", for the full staged structural-versus-semantic boundary
this follows, and the known, deliberately-unresolved conflict with the
current vendored `invalid-policy-bundle` canonical fixture (which classifies
its duplicate-`rule_id` scenario as `invalid_policy_bundle`) — that fixture
is not modified by this file or by `engine.py`, and reconciling it is
upstream `basis-schemas` work, tracked as a PR 28 blocker in the roadmap
plan's PR 27B status note.
"""

from __future__ import annotations

import ast
import inspect

import pytest

from basis_core.audit.operation_aware.evaluation_trace import (
    EvaluationStatus,
    EvaluationTrace,
    TraceBundleApplicability,
    TraceFailureReason,
    TraceOutcome,
)
from basis_core.decisions.operation_aware import (
    OperationAwareDecisionRequest,
    OperationAwareFailureReason,
)
from basis_core.evaluation.operation_aware.engine import OperationAwareEvaluationEngine
from basis_core.policy.operation_aware.aggregation import (
    OperationAwarePolicyOutcome,
    PolicyAggregationStatus,
)
from basis_core.policy.operation_aware.applicability import ApplicabilityResult
from basis_core.policy.operation_aware.bundle import PolicyBundle

# ══════════════════════════════════════════════════════════════════════════
# Shared construction helpers
# ══════════════════════════════════════════════════════════════════════════

_SUBJECT_ID = "svc-engine-test"


def _build_request(**overrides: object) -> OperationAwareDecisionRequest:
    kwargs: dict[str, object] = {
        "request_id": "req-engine-fixture-0001",
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
    bundle_id: str = "bundle-engine-fixture",
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


def _match_condition(condition_id: str, *, subject_id: str = _SUBJECT_ID) -> dict[str, object]:
    """Deterministically evaluates to a MATCH."""
    return {
        "condition_id": condition_id,
        "field_path": "subject_id",
        "operator": "equals",
        "expected_value": subject_id,
    }


def _no_match_condition(condition_id: str) -> dict[str, object]:
    """Deterministically evaluates to a NO_MATCH."""
    return {
        "condition_id": condition_id,
        "field_path": "subject_id",
        "operator": "equals",
        "expected_value": "not-the-subject",
    }


def _error_condition(condition_id: str) -> dict[str, object]:
    """Deterministically evaluates to an ERROR: `future_operator` is
    structurally valid but unimplemented — the same convention every other
    operation-aware test file uses."""
    return {
        "condition_id": condition_id,
        "field_path": "subject_id",
        "operator": "future_operator",
        "expected_value": "irrelevant",
    }


def _duplicate_rule_id_bundle() -> PolicyBundle:
    """The canonical-vector-shaped `invalid-policy-bundle` scenario: two
    rules sharing one `rule_id`. `PolicyBundle`'s own constructor does not
    reject this (duplicate-`rule_id` rejection is `validate_policy_bundle`'s
    job, PR 15) — so this builds via ordinary `model_validate`, exactly like
    a real caller would. This is a `SemanticPolicyValidationError`
    (`DuplicateRuleIdError`) case — reachable through the engine's typed
    entry point — which the engine maps to `POLICY_VALIDATION_FAILURE`; see
    this file's module docstring for the known, deliberately-unresolved
    conflict with the vendored fixture's own `invalid_policy_bundle`
    classification of this same scenario."""
    return _build_bundle(
        rules=[
            _rule_dict("dup-rule", effect="allow", action="read:ahu"),
            _rule_dict("dup-rule", effect="deny", action="write:ahu"),
        ]
    )


def _duplicate_condition_id_bundle() -> PolicyBundle:
    """A `SemanticPolicyValidationError` (`DuplicateConditionIdError`) case:
    one rule carrying two conditions sharing a `condition_id`.
    `OperationAwarePolicyRule`'s own ordinary constructor already refuses to
    build this shape, so — mirroring `test_policy_validation.py`'s own
    `_bundle_with_duplicate_condition_ids_via_model_construct` exactly —
    this uses pydantic's public `model_construct` ("already-validated data")
    escape hatch to build a real, correctly-typed `PolicyBundle` that
    exhibits the violation without weakening or bypassing `rule.py`'s own
    validator for any ordinary caller."""
    from basis_core.policy.operation_aware.condition import PolicyCondition
    from basis_core.policy.operation_aware.rule import OperationAwarePolicyRule, RuleEffect

    cond_a = PolicyCondition(**_match_condition("cond-duplicate"))
    cond_b = PolicyCondition(
        condition_id="cond-duplicate",
        field_path="subject_id",
        operator="equals",
        expected_value="not-the-subject",
    )
    rule = OperationAwarePolicyRule.model_construct(
        rule_id="rule-bypassed",
        effect=RuleEffect.ALLOW,
        match=None,
        conditions=[cond_a, cond_b],
        reason_code=None,
        explanation=None,
    )
    return PolicyBundle.model_construct(
        bundle_id="bundle-condition-dup-probe",
        bundle_version="1.0.0",
        schema_version="0.2.0",
        policy_owner="test-owner",
        scope=None,
        rules=[rule],
        description=None,
        source_ref=None,
        approval_ref=None,
        created_at=None,
        updated_at=None,
        compatibility_target=None,
        deprecated=False,
        replaced_by=None,
    )


# ══════════════════════════════════════════════════════════════════════════
# Construction and naming
# ══════════════════════════════════════════════════════════════════════════


class TestConstructionAndNaming:
    def test_engine_exists_in_evaluation_operation_aware_package(self) -> None:
        assert OperationAwareEvaluationEngine.__module__ == (
            "basis_core.evaluation.operation_aware.engine"
        )

    def test_operation_aware_policy_engine_does_not_exist(self) -> None:
        import basis_core.evaluation.operation_aware.engine as engine_module

        assert not hasattr(engine_module, "OperationAwarePolicyEngine")

    def test_engine_adds_no_stable_package_level_public_export(self) -> None:
        import basis_core.evaluation as evaluation_package
        import basis_core.evaluation.operation_aware as operation_aware_package

        assert not hasattr(evaluation_package, "OperationAwareEvaluationEngine")
        assert not hasattr(operation_aware_package, "OperationAwareEvaluationEngine")

    def test_engine_holds_no_mutable_instance_state(self) -> None:
        engine = OperationAwareEvaluationEngine()
        assert vars(engine) == {}

    def test_engine_has_no_constructor_dependencies(self) -> None:
        # Must be constructible with zero arguments — no configurable
        # strategy object, no policy source, no cache.
        OperationAwareEvaluationEngine()


# ══════════════════════════════════════════════════════════════════════════
# Stage ordering
# ══════════════════════════════════════════════════════════════════════════


class TestStageOrdering:
    def test_stages_invoked_in_required_order_for_an_applicable_matched_allow(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import basis_core.evaluation.operation_aware.engine as engine_module

        calls: list[str] = []

        real_validate = engine_module.validate_policy_bundle
        real_determine = engine_module.determine_applicability
        real_select = engine_module.select_candidate_rules
        real_evaluate_conditions = engine_module.evaluate_rule_conditions
        real_aggregate = engine_module.aggregate_policy_outcome
        real_assemble_rule_evidence = engine_module.assemble_rule_evidence
        real_assemble_trace = engine_module.assemble_evaluation_trace

        def spy(name: str, fn: object) -> object:
            def wrapper(*args: object, **kwargs: object) -> object:
                calls.append(name)
                return fn(*args, **kwargs)  # type: ignore[operator]

            return wrapper

        monkeypatch.setattr(engine_module, "validate_policy_bundle", spy("validate", real_validate))
        monkeypatch.setattr(
            engine_module, "determine_applicability", spy("applicability", real_determine)
        )
        monkeypatch.setattr(engine_module, "select_candidate_rules", spy("select", real_select))
        monkeypatch.setattr(
            engine_module,
            "evaluate_rule_conditions",
            spy("condition_eval", real_evaluate_conditions),
        )
        monkeypatch.setattr(
            engine_module, "aggregate_policy_outcome", spy("aggregate", real_aggregate)
        )
        monkeypatch.setattr(
            engine_module,
            "assemble_rule_evidence",
            spy("rule_evidence", real_assemble_rule_evidence),
        )
        monkeypatch.setattr(
            engine_module, "assemble_evaluation_trace", spy("trace_assembly", real_assemble_trace)
        )

        engine = OperationAwareEvaluationEngine()
        trace = engine.evaluate(
            request=_build_request(),
            bundle=_build_bundle(),
            trace_id="trace-order-1",
        )

        assert trace.outcome is TraceOutcome.ALLOW
        assert calls == [
            "validate",
            "applicability",
            "select",
            "condition_eval",
            "aggregate",
            "rule_evidence",
            "trace_assembly",
        ], calls

    def test_integration_shaped_evaluation_with_real_implementations(self) -> None:
        """At least one test exercises every real stage together, unmocked."""
        engine = OperationAwareEvaluationEngine()
        trace = engine.evaluate(
            request=_build_request(),
            bundle=_build_bundle(),
            trace_id="trace-integration-1",
        )
        assert isinstance(trace, EvaluationTrace)
        assert trace.evaluation_status is EvaluationStatus.COMPLETED
        assert trace.outcome is TraceOutcome.ALLOW


# ══════════════════════════════════════════════════════════════════════════
# Non-applicable bundle
# ══════════════════════════════════════════════════════════════════════════


class TestNonApplicableBundle:
    def _non_applicable_bundle(self) -> PolicyBundle:
        return _build_bundle(scope={"actions": ["write:ahu"]})

    def test_produces_completed_not_applicable(self) -> None:
        engine = OperationAwareEvaluationEngine()
        trace = engine.evaluate(
            request=_build_request(action="read:ahu"),
            bundle=self._non_applicable_bundle(),
            trace_id="trace-na-1",
        )
        assert trace.evaluation_status is EvaluationStatus.COMPLETED
        assert trace.outcome is TraceOutcome.NOT_APPLICABLE
        assert trace.bundle_applicability is TraceBundleApplicability.NOT_APPLICABLE

    def test_produces_empty_rule_evidence(self) -> None:
        engine = OperationAwareEvaluationEngine()
        trace = engine.evaluate(
            request=_build_request(action="read:ahu"),
            bundle=self._non_applicable_bundle(),
            trace_id="trace-na-2",
        )
        assert trace.rule_evidence == []

    def test_does_not_invoke_selector_or_condition_evaluation(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import basis_core.evaluation.operation_aware.engine as engine_module

        def _boom(*args: object, **kwargs: object) -> object:
            raise AssertionError(
                "selector/condition evaluation must not run for a non-applicable bundle"
            )

        monkeypatch.setattr(engine_module, "select_candidate_rules", _boom)
        monkeypatch.setattr(engine_module, "evaluate_rule_conditions", _boom)

        engine = OperationAwareEvaluationEngine()
        trace = engine.evaluate(
            request=_build_request(action="read:ahu"),
            bundle=self._non_applicable_bundle(),
            trace_id="trace-na-3",
        )
        assert trace.outcome is TraceOutcome.NOT_APPLICABLE

    def test_does_not_convert_to_deny(self) -> None:
        engine = OperationAwareEvaluationEngine()
        trace = engine.evaluate(
            request=_build_request(action="read:ahu"),
            bundle=self._non_applicable_bundle(),
            trace_id="trace-na-4",
        )
        assert trace.outcome is not TraceOutcome.DENY

    def test_preserves_identifiers(self) -> None:
        engine = OperationAwareEvaluationEngine()
        request = _build_request(action="read:ahu", correlation_id="corr-na-1")
        bundle = self._non_applicable_bundle()
        trace = engine.evaluate(request=request, bundle=bundle, trace_id="trace-na-5")
        assert trace.trace_id == "trace-na-5"
        assert trace.request_id == request.request_id
        assert trace.correlation_id == "corr-na-1"
        assert trace.bundle_id == bundle.bundle_id
        assert trace.bundle_version == bundle.bundle_version


# ══════════════════════════════════════════════════════════════════════════
# Allow
# ══════════════════════════════════════════════════════════════════════════


class TestAllow:
    def test_applicable_matched_allow_produces_completed_allow(self) -> None:
        engine = OperationAwareEvaluationEngine()
        trace = engine.evaluate(
            request=_build_request(),
            bundle=_build_bundle(rules=[_rule_dict("allow-1")]),
            trace_id="trace-allow-1",
        )
        assert trace.evaluation_status is EvaluationStatus.COMPLETED
        assert trace.outcome is TraceOutcome.ALLOW

    def test_aggregation_reason_code_is_reflected_in_trace(self) -> None:
        engine = OperationAwareEvaluationEngine()
        trace = engine.evaluate(
            request=_build_request(),
            bundle=_build_bundle(rules=[_rule_dict("allow-1")]),
            trace_id="trace-allow-2",
        )
        assert trace.reason_code == "allow_rule_matched"

    def test_matching_rule_evidence_is_included(self) -> None:
        engine = OperationAwareEvaluationEngine()
        trace = engine.evaluate(
            request=_build_request(),
            bundle=_build_bundle(rules=[_rule_dict("allow-1")]),
            trace_id="trace-allow-3",
        )
        assert len(trace.rule_evidence) == 1
        assert trace.rule_evidence[0].rule_id == "allow-1"

    def test_no_synthetic_condition_evidence_for_a_rule_without_conditions(self) -> None:
        engine = OperationAwareEvaluationEngine()
        trace = engine.evaluate(
            request=_build_request(),
            bundle=_build_bundle(rules=[_rule_dict("allow-1")]),
            trace_id="trace-allow-4",
        )
        assert trace.rule_evidence[0].condition_results is None


# ══════════════════════════════════════════════════════════════════════════
# Deny precedence
# ══════════════════════════════════════════════════════════════════════════


class TestDenyPrecedence:
    def test_matched_allow_plus_matched_deny_produces_deny(self) -> None:
        engine = OperationAwareEvaluationEngine()
        bundle = _build_bundle(
            rules=[
                _rule_dict("allow-1", effect="allow"),
                _rule_dict("deny-1", effect="deny"),
            ]
        )
        trace = engine.evaluate(request=_build_request(), bundle=bundle, trace_id="trace-deny-1")
        assert trace.outcome is TraceOutcome.DENY
        assert trace.reason_code == "deny_rule_matched"

    def test_reversing_authored_rule_order_does_not_change_outcome(self) -> None:
        engine = OperationAwareEvaluationEngine()
        forward = _build_bundle(
            rules=[
                _rule_dict("allow-1", effect="allow"),
                _rule_dict("deny-1", effect="deny"),
            ]
        )
        reversed_bundle = _build_bundle(
            rules=[
                _rule_dict("deny-1", effect="deny"),
                _rule_dict("allow-1", effect="allow"),
            ]
        )
        forward_trace = engine.evaluate(
            request=_build_request(), bundle=forward, trace_id="trace-deny-2"
        )
        reversed_trace = engine.evaluate(
            request=_build_request(), bundle=reversed_bundle, trace_id="trace-deny-2"
        )
        assert forward_trace.outcome is reversed_trace.outcome is TraceOutcome.DENY
        assert forward_trace == reversed_trace

    def test_ordered_evidence_is_assembled_before_any_short_circuit(self) -> None:
        """Both rules' evidence must appear — the engine does not stop
        assembling evidence early just because a deny was found."""
        engine = OperationAwareEvaluationEngine()
        bundle = _build_bundle(
            rules=[
                _rule_dict("allow-1", effect="allow"),
                _rule_dict("deny-1", effect="deny"),
            ]
        )
        trace = engine.evaluate(request=_build_request(), bundle=bundle, trace_id="trace-deny-3")
        assert {evidence.rule_id for evidence in trace.rule_evidence} == {"allow-1", "deny-1"}

    def test_deny_precedence_comes_from_aggregation_not_duplicated_engine_logic(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The engine must trust `aggregate_policy_outcome`'s result as
        authoritative rather than re-deriving deny precedence itself: if we
        force aggregation to report ALLOW despite a matched deny rule being
        present, the engine's trace must reflect ALLOW (proving it performs
        no independent re-scan of `evaluated_rules`)."""
        import basis_core.evaluation.operation_aware.engine as engine_module
        from basis_core.domain.operation_aware_vocabulary import ReasonCode
        from basis_core.policy.operation_aware.aggregation import PolicyAggregationResult

        forced_result = PolicyAggregationResult(
            status=PolicyAggregationStatus.COMPLETED,
            outcome=OperationAwarePolicyOutcome.ALLOW,
            failure_reason=None,
            reason_code=ReasonCode("allow_rule_matched"),
        )
        monkeypatch.setattr(
            engine_module, "aggregate_policy_outcome", lambda *a, **k: forced_result
        )

        engine = OperationAwareEvaluationEngine()
        bundle = _build_bundle(
            rules=[
                _rule_dict("allow-1", effect="allow"),
                _rule_dict("deny-1", effect="deny"),
            ]
        )
        trace = engine.evaluate(request=_build_request(), bundle=bundle, trace_id="trace-deny-4")
        assert trace.outcome is TraceOutcome.ALLOW


# ══════════════════════════════════════════════════════════════════════════
# Default deny
# ══════════════════════════════════════════════════════════════════════════


class TestDefaultDeny:
    def test_no_matched_allow_or_deny_produces_deny(self) -> None:
        engine = OperationAwareEvaluationEngine()
        bundle = _build_bundle(rules=[_rule_dict("allow-1", action="write:ahu")])
        trace = engine.evaluate(
            request=_build_request(action="read:ahu"), bundle=bundle, trace_id="trace-default-1"
        )
        assert trace.outcome is TraceOutcome.DENY
        assert trace.reason_code == "no_allow_rule_matched"

    def test_default_deny_reason_is_distinguishable_from_explicit_deny(self) -> None:
        engine = OperationAwareEvaluationEngine()
        default_bundle = _build_bundle(rules=[_rule_dict("allow-1", action="write:ahu")])
        explicit_bundle = _build_bundle(rules=[_rule_dict("deny-1", effect="deny")])
        default_trace = engine.evaluate(
            request=_build_request(action="read:ahu"),
            bundle=default_bundle,
            trace_id="trace-default-2",
        )
        explicit_trace = engine.evaluate(
            request=_build_request(action="read:ahu"),
            bundle=explicit_bundle,
            trace_id="trace-default-3",
        )
        assert default_trace.outcome is explicit_trace.outcome is TraceOutcome.DENY
        assert default_trace.reason_code != explicit_trace.reason_code

    def test_nonmatching_rule_evidence_is_honest_and_ordered(self) -> None:
        engine = OperationAwareEvaluationEngine()
        bundle = _build_bundle(rules=[_rule_dict("allow-1", action="write:ahu")])
        trace = engine.evaluate(
            request=_build_request(action="read:ahu"), bundle=bundle, trace_id="trace-default-4"
        )
        assert len(trace.rule_evidence) == 1
        assert trace.rule_evidence[0].rule_id == "allow-1"
        assert trace.rule_evidence[0].rule_result.value == "not_matched"


# ══════════════════════════════════════════════════════════════════════════
# Condition behavior
# ══════════════════════════════════════════════════════════════════════════


class TestConditionBehavior:
    def test_matching_condition_produces_matched_rule(self) -> None:
        engine = OperationAwareEvaluationEngine()
        bundle = _build_bundle(rules=[_rule_dict("cond-1", conditions=[_match_condition("c1")])])
        trace = engine.evaluate(request=_build_request(), bundle=bundle, trace_id="trace-cond-1")
        assert trace.outcome is TraceOutcome.ALLOW
        assert trace.rule_evidence[0].rule_result.value == "matched"
        assert trace.rule_evidence[0].condition_results is not None
        assert trace.rule_evidence[0].condition_results[0].result.value == "matched"

    def test_condition_no_match_produces_nonmatching_rule(self) -> None:
        engine = OperationAwareEvaluationEngine()
        bundle = _build_bundle(rules=[_rule_dict("cond-1", conditions=[_no_match_condition("c1")])])
        trace = engine.evaluate(request=_build_request(), bundle=bundle, trace_id="trace-cond-2")
        assert trace.outcome is TraceOutcome.DENY
        assert trace.reason_code == "no_allow_rule_matched"
        assert trace.rule_evidence[0].rule_result.value == "not_matched"

    def test_condition_error_produces_failed_trace_with_condition_evaluation_error(
        self,
    ) -> None:
        engine = OperationAwareEvaluationEngine()
        bundle = _build_bundle(rules=[_rule_dict("cond-1", conditions=[_error_condition("c1")])])
        trace = engine.evaluate(request=_build_request(), bundle=bundle, trace_id="trace-cond-3")
        assert trace.evaluation_status is EvaluationStatus.FAILED
        assert trace.outcome is None
        assert trace.failure_reason is TraceFailureReason.CONDITION_EVALUATION_ERROR

    def test_failed_trace_carries_error_rule_evidence(self) -> None:
        engine = OperationAwareEvaluationEngine()
        bundle = _build_bundle(rules=[_rule_dict("cond-1", conditions=[_error_condition("c1")])])
        trace = engine.evaluate(request=_build_request(), bundle=bundle, trace_id="trace-cond-4")
        assert len(trace.rule_evidence) == 1
        assert trace.rule_evidence[0].rule_result.value == "error"
        assert trace.rule_evidence[0].condition_results is not None
        assert trace.rule_evidence[0].condition_results[0].result.value == "error"

    def test_condition_failure_is_independent_of_rule_order(self) -> None:
        engine = OperationAwareEvaluationEngine()
        forward = _build_bundle(
            rules=[
                _rule_dict("allow-1", effect="allow"),
                _rule_dict("error-1", conditions=[_error_condition("c1")]),
            ]
        )
        backward = _build_bundle(
            rules=[
                _rule_dict("error-1", conditions=[_error_condition("c1")]),
                _rule_dict("allow-1", effect="allow"),
            ]
        )
        forward_trace = engine.evaluate(
            request=_build_request(), bundle=forward, trace_id="trace-cond-5"
        )
        backward_trace = engine.evaluate(
            request=_build_request(), bundle=backward, trace_id="trace-cond-5"
        )
        assert (
            forward_trace.evaluation_status
            is backward_trace.evaluation_status
            is (EvaluationStatus.FAILED)
        )
        assert forward_trace.failure_reason is backward_trace.failure_reason


# ══════════════════════════════════════════════════════════════════════════
# Invalid policy
# ══════════════════════════════════════════════════════════════════════════


_INVALID_BUNDLE_BUILDERS = pytest.mark.parametrize(
    "build_bundle",
    [_duplicate_rule_id_bundle, _duplicate_condition_id_bundle],
    ids=["duplicate-rule-id", "duplicate-condition-id"],
)


class TestInvalidPolicy:
    @_INVALID_BUNDLE_BUILDERS
    def test_semantic_validation_happens_before_applicability(
        self, monkeypatch: pytest.MonkeyPatch, build_bundle: object
    ) -> None:
        import basis_core.evaluation.operation_aware.engine as engine_module

        def _boom(*args: object, **kwargs: object) -> object:
            raise AssertionError("applicability must not run for an invalid bundle")

        monkeypatch.setattr(engine_module, "determine_applicability", _boom)

        engine = OperationAwareEvaluationEngine()
        trace = engine.evaluate(
            request=_build_request(),
            bundle=build_bundle(),  # type: ignore[operator]
            trace_id="trace-invalid-1",
        )
        assert trace.evaluation_status is EvaluationStatus.FAILED

    @_INVALID_BUNDLE_BUILDERS
    def test_duplicate_identity_never_reaches_selector_or_condition_evaluation(
        self, monkeypatch: pytest.MonkeyPatch, build_bundle: object
    ) -> None:
        import basis_core.evaluation.operation_aware.engine as engine_module

        def _boom(*args: object, **kwargs: object) -> object:
            raise AssertionError(
                "selection/condition evaluation must not run for an invalid bundle"
            )

        monkeypatch.setattr(engine_module, "select_candidate_rules", _boom)
        monkeypatch.setattr(engine_module, "evaluate_rule_conditions", _boom)

        engine = OperationAwareEvaluationEngine()
        engine.evaluate(
            request=_build_request(),
            bundle=build_bundle(),  # type: ignore[operator]
            trace_id="trace-invalid-2",
        )

    @_INVALID_BUNDLE_BUILDERS
    def test_duplicate_identity_never_reaches_aggregation_or_rule_evidence_assembly(
        self, monkeypatch: pytest.MonkeyPatch, build_bundle: object
    ) -> None:
        import basis_core.evaluation.operation_aware.engine as engine_module

        def _boom(*args: object, **kwargs: object) -> object:
            raise AssertionError(
                "aggregation/rule-evidence assembly must not run for an invalid bundle"
            )

        monkeypatch.setattr(engine_module, "aggregate_policy_outcome", _boom)
        monkeypatch.setattr(engine_module, "assemble_rule_evidence", _boom)

        engine = OperationAwareEvaluationEngine()
        engine.evaluate(
            request=_build_request(),
            bundle=build_bundle(),  # type: ignore[operator]
            trace_id="trace-invalid-3",
        )

    @_INVALID_BUNDLE_BUILDERS
    def test_invalid_policy_never_produces_allow(self, build_bundle: object) -> None:
        engine = OperationAwareEvaluationEngine()
        trace = engine.evaluate(
            request=_build_request(),
            bundle=build_bundle(),  # type: ignore[operator]
            trace_id="trace-invalid-4",
        )
        assert trace.outcome is not TraceOutcome.ALLOW
        assert trace.outcome is None

    @_INVALID_BUNDLE_BUILDERS
    def test_exact_approved_failure_category_is_used(self, build_bundle: object) -> None:
        """See `engine.py`'s docstring, 'Policy-validation failure mapping':
        this engine follows the typed structural-versus-semantic validation
        boundary, so a reachable `SemanticPolicyValidationError` always maps
        to `policy_validation_failure` — not `invalid_policy_bundle`, which
        is unreachable through this engine's typed entry point."""
        engine = OperationAwareEvaluationEngine()
        trace = engine.evaluate(
            request=_build_request(),
            bundle=build_bundle(),  # type: ignore[operator]
            trace_id="trace-invalid-5",
        )
        assert trace.failure_reason is TraceFailureReason.POLICY_VALIDATION_FAILURE

    @_INVALID_BUNDLE_BUILDERS
    def test_no_rule_evidence_is_fabricated(self, build_bundle: object) -> None:
        engine = OperationAwareEvaluationEngine()
        trace = engine.evaluate(
            request=_build_request(),
            bundle=build_bundle(),  # type: ignore[operator]
            trace_id="trace-invalid-6",
        )
        assert trace.rule_evidence == []

    @_INVALID_BUNDLE_BUILDERS
    def test_bundle_applicability_is_null_for_a_validation_failure(
        self, build_bundle: object
    ) -> None:
        engine = OperationAwareEvaluationEngine()
        trace = engine.evaluate(
            request=_build_request(),
            bundle=build_bundle(),  # type: ignore[operator]
            trace_id="trace-invalid-7",
        )
        assert trace.bundle_applicability is None

    @_INVALID_BUNDLE_BUILDERS
    def test_bundle_identity_is_still_preserved_on_a_validation_failure(
        self, build_bundle: object
    ) -> None:
        engine = OperationAwareEvaluationEngine()
        bundle = build_bundle()  # type: ignore[operator]
        trace = engine.evaluate(request=_build_request(), bundle=bundle, trace_id="trace-invalid-8")
        assert trace.bundle_id == bundle.bundle_id
        assert trace.bundle_version == bundle.bundle_version

    def test_engine_does_not_accept_a_raw_mapping_in_place_of_a_typed_bundle(self) -> None:
        """The engine's `bundle` parameter is annotated `PolicyBundle` only
        — never a union with `dict`/`Mapping` — so a raw mapping is a type
        error, not a value this engine is expected to structurally validate
        itself. This is a static-signature check, not a runtime-coercion
        test: this engine's typed entry point never accepts, and never
        needs to reject, a raw dictionary in place of `bundle`."""
        import inspect

        signature = inspect.signature(OperationAwareEvaluationEngine.evaluate)
        bundle_annotation = signature.parameters["bundle"].annotation
        assert bundle_annotation in ("PolicyBundle", PolicyBundle)

    def test_structural_validation_failure_is_not_synthetically_exercised(self) -> None:
        """This file deliberately does not construct a
        `StructuralPolicyValidationError` case and force it through the
        engine: doing so would require either bypassing `PolicyBundle`
        construction (defeating the point — the engine's own contract is
        that `bundle` already is one) or accepting a raw mapping (which the
        engine's signature refuses). `StructuralPolicyValidationError` is
        unreachable through this engine's typed entry point by
        construction, not by an untested code path — see `engine.py`'s
        docstring, "Policy-validation failure mapping"."""
        import basis_core.evaluation.operation_aware.engine as engine_module

        # The engine module does not even import `StructuralPolicyValidationError`
        # — only `SemanticPolicyValidationError`, the one reachable category.
        assert not hasattr(engine_module, "StructuralPolicyValidationError")


# ══════════════════════════════════════════════════════════════════════════
# Mapping integrity
# ══════════════════════════════════════════════════════════════════════════


class TestMappingIntegrity:
    def test_every_applicability_result_member_is_mapped(self) -> None:
        import basis_core.evaluation.operation_aware.engine as engine_module

        assert set(ApplicabilityResult) == set(
            engine_module._APPLICABILITY_TO_TRACE_BUNDLE_APPLICABILITY.keys()
        )

    def test_every_policy_aggregation_status_member_is_mapped(self) -> None:
        import basis_core.evaluation.operation_aware.engine as engine_module

        assert set(PolicyAggregationStatus) == set(
            engine_module._AGGREGATION_STATUS_TO_EVALUATION_STATUS.keys()
        )

    def test_every_policy_outcome_member_is_mapped(self) -> None:
        import basis_core.evaluation.operation_aware.engine as engine_module

        assert set(OperationAwarePolicyOutcome) == set(
            engine_module._POLICY_OUTCOME_TO_TRACE_OUTCOME.keys()
        )

    def test_every_failure_reason_member_is_mapped(self) -> None:
        import basis_core.evaluation.operation_aware.engine as engine_module

        assert set(OperationAwareFailureReason) == set(
            engine_module._FAILURE_REASON_TO_TRACE_FAILURE_REASON.keys()
        )

    def test_mapping_completeness_fails_if_a_member_is_missing(self) -> None:
        """Directly demonstrates what the completeness tests above guard
        against: an incomplete mapping table is detectable by simple set
        comparison, not by `.value` coercion."""
        import basis_core.evaluation.operation_aware.engine as engine_module

        incomplete = dict(engine_module._APPLICABILITY_TO_TRACE_BUNDLE_APPLICABILITY)
        del incomplete[ApplicabilityResult.APPLICABLE]
        assert set(ApplicabilityResult) != set(incomplete.keys())

    def test_no_value_coercion_is_used_as_the_mapping_implementation(self) -> None:
        """Detects the `TraceEnum(policy_enum.value)` anti-pattern via AST
        (a call whose argument is a `.value` attribute access) rather than a
        blunt substring scan, which would also (falsely) flag this module's
        own docstring prose describing the anti-pattern to avoid."""
        import basis_core.evaluation.operation_aware.engine as engine_module

        source = inspect.getsource(engine_module)
        tree = ast.parse(source)
        coercions = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and any(isinstance(arg, ast.Attribute) and arg.attr == "value" for arg in node.args)
        ]
        assert coercions == []

    def test_decisions_and_trace_failure_vocabularies_remain_explicitly_mapped(self) -> None:
        import basis_core.evaluation.operation_aware.engine as engine_module

        for member, trace_member in engine_module._FAILURE_REASON_TO_TRACE_FAILURE_REASON.items():
            assert member.value == trace_member.value


# ══════════════════════════════════════════════════════════════════════════
# Determinism
# ══════════════════════════════════════════════════════════════════════════


class TestDeterminism:
    def test_same_inputs_and_trace_id_produce_equal_traces(self) -> None:
        engine = OperationAwareEvaluationEngine()
        bundle = _build_bundle(rules=[_rule_dict("allow-1")])
        first = engine.evaluate(request=_build_request(), bundle=bundle, trace_id="trace-det-1")
        second = engine.evaluate(request=_build_request(), bundle=bundle, trace_id="trace-det-1")
        assert first == second

    def test_repeated_calls_do_not_mutate_the_request_or_bundle(self) -> None:
        engine = OperationAwareEvaluationEngine()
        request = _build_request()
        bundle = _build_bundle(rules=[_rule_dict("allow-1")])
        request_before = request.model_dump(mode="json")
        bundle_before = bundle.model_dump(mode="json")
        for trace_id in ("trace-det-2", "trace-det-3", "trace-det-4"):
            engine.evaluate(request=request, bundle=bundle, trace_id=trace_id)
        assert request.model_dump(mode="json") == request_before
        assert bundle.model_dump(mode="json") == bundle_before

    def test_no_clock_uuid_random_or_environment_dependency(self) -> None:
        import basis_core.evaluation.operation_aware.engine as engine_module

        source = inspect.getsource(engine_module)
        tree = ast.parse(source)
        imported_modules: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                imported_modules.append(node.module)
            elif isinstance(node, ast.Import):
                imported_modules.extend(alias.name for alias in node.names)

        forbidden_prefixes = ("uuid", "random", "os", "time", "datetime", "socket", "pathlib")
        violations = [
            module
            for module in imported_modules
            if any(
                module == prefix or module.startswith(prefix + ".") for prefix in forbidden_prefixes
            )
        ]
        assert violations == [], (
            f"engine.py imports a forbidden nondeterministic module: {violations}"
        )

    def test_deterministic_rule_evidence_ordering_is_preserved(self) -> None:
        engine = OperationAwareEvaluationEngine()
        bundle_a = _build_bundle(
            rules=[_rule_dict("rule-b"), _rule_dict("rule-a")], bundle_id="bundle-order-a"
        )
        bundle_b = _build_bundle(
            rules=[_rule_dict("rule-a"), _rule_dict("rule-b")], bundle_id="bundle-order-b"
        )
        trace_a = engine.evaluate(
            request=_build_request(), bundle=bundle_a, trace_id="trace-order-a"
        )
        trace_b = engine.evaluate(
            request=_build_request(), bundle=bundle_b, trace_id="trace-order-b"
        )
        order_a = [e.rule_id for e in trace_a.rule_evidence]
        order_b = [e.rule_id for e in trace_b.rule_evidence]
        assert order_a == order_b == ["rule-a", "rule-b"]


# ══════════════════════════════════════════════════════════════════════════
# Identity integrity
# ══════════════════════════════════════════════════════════════════════════


class TestIdentityIntegrity:
    def test_engine_composition_never_triggers_a_rule_identity_mismatch(self) -> None:
        """`RuleIdentityMismatchError` (`trace_assembly.py`) remains
        meaningful — proven by its own focused test file
        (`test_trace_assembly.py`) — but the engine's own pairing of rule
        and evaluation must never trigger it in ordinary operation, across
        multiple rules."""
        engine = OperationAwareEvaluationEngine()
        bundle = _build_bundle(rules=[_rule_dict("r1"), _rule_dict("r2", action="write:ahu")])
        trace = engine.evaluate(request=_build_request(), bundle=bundle, trace_id="trace-id-1")
        assert {e.rule_id for e in trace.rule_evidence} == {"r1", "r2"}

    def test_request_id_comes_from_the_request(self) -> None:
        engine = OperationAwareEvaluationEngine()
        request = _build_request(request_id="req-distinct-id")
        trace = engine.evaluate(
            request=request, bundle=_build_bundle(), trace_id="trace-distinct-id"
        )
        assert trace.request_id == "req-distinct-id"
        assert trace.request_id != trace.trace_id

    def test_correlation_id_comes_from_the_request(self) -> None:
        engine = OperationAwareEvaluationEngine()
        request = _build_request(correlation_id="corr-distinct")
        trace = engine.evaluate(request=request, bundle=_build_bundle(), trace_id="trace-corr-1")
        assert trace.correlation_id == "corr-distinct"

    def test_trace_id_comes_only_from_the_caller(self) -> None:
        engine = OperationAwareEvaluationEngine()
        trace = engine.evaluate(
            request=_build_request(), bundle=_build_bundle(), trace_id="trace-caller-supplied"
        )
        assert trace.trace_id == "trace-caller-supplied"

    def test_bundle_id_and_version_come_from_the_bundle(self) -> None:
        engine = OperationAwareEvaluationEngine()
        bundle = _build_bundle(bundle_id="bundle-identity-check")
        trace = engine.evaluate(
            request=_build_request(), bundle=bundle, trace_id="trace-bundle-identity"
        )
        assert trace.bundle_id == "bundle-identity-check"
        assert trace.bundle_version == bundle.bundle_version


# ══════════════════════════════════════════════════════════════════════════
# Compatibility
# ══════════════════════════════════════════════════════════════════════════


class TestCompatibility:
    def test_v01_policy_engine_remains_unchanged(self) -> None:
        from basis_core.domain.subject import Subject
        from basis_core.policy.engine import PolicyEngine
        from basis_core.policy.engine import PolicyOutcome as V01PolicyOutcome
        from basis_core.policy.rules import RolePolicyRule

        role_table = {"read:ahu": {"operator"}}
        v01_engine = PolicyEngine(policies=[RolePolicyRule(role_table)])
        subject = Subject(id="sub-1", name="Test Subject", roles=["operator"])

        before = v01_engine.evaluate(subject, "read:ahu")
        assert before.outcome is V01PolicyOutcome.ALLOW

        engine = OperationAwareEvaluationEngine()
        engine.evaluate(request=_build_request(), bundle=_build_bundle(), trace_id="trace-compat-1")

        after = v01_engine.evaluate(subject, "read:ahu")
        assert after.outcome is V01PolicyOutcome.ALLOW
        assert before.outcome == after.outcome

    def test_v01_enforcement_point_remains_unchanged(self) -> None:
        from basis_core.audit.writer import NullAuditWriter
        from basis_core.decisions.models import DecisionOutcome as V01DecisionOutcome
        from basis_core.decisions.models import DecisionRequest
        from basis_core.enforcement.enforcement import EnforcementPoint
        from basis_core.policy.engine import PolicyEngine
        from basis_core.policy.rules import RolePolicyRule

        v01_engine = PolicyEngine(policies=[RolePolicyRule({"read:ahu": {"operator"}})])
        enforcement_point = EnforcementPoint(engine=v01_engine, audit_writer=NullAuditWriter())
        request = DecisionRequest(subject_id="sub-1", action="read:ahu")

        before = enforcement_point.evaluate(request)
        assert before.outcome is V01DecisionOutcome.DENY  # no roles on the raw request

        engine = OperationAwareEvaluationEngine()
        engine.evaluate(request=_build_request(), bundle=_build_bundle(), trace_id="trace-compat-2")

        after = enforcement_point.evaluate(request)
        assert after.outcome is V01DecisionOutcome.DENY
        assert before.outcome == after.outcome

    def test_engine_does_not_import_adapters_or_enforcement(self) -> None:
        import basis_core.evaluation.operation_aware.engine as engine_module

        source = inspect.getsource(engine_module)
        tree = ast.parse(source)
        imported_modules: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                imported_modules.append(node.module)
            elif isinstance(node, ast.Import):
                imported_modules.extend(alias.name for alias in node.names)

        assert not any(m.startswith("basis_core.adapters") for m in imported_modules)
        assert not any(m.startswith("basis_core.enforcement") for m in imported_modules)
