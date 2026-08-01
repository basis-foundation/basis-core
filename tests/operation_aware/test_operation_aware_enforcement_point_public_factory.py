"""
tests/operation_aware/test_operation_aware_enforcement_point_public_factory.py
— tests for `OperationAwareEnforcementPoint.for_bundle()`, the public
downstream construction factory added by the upstream correction
`fix/public-operation-aware-enforcement-factory`.

Context: `OperationAwareEnforcementPoint` is the documented public
downstream entry point (`docs/public-api.md`), but its direct constructor
requires an `OperationAwareEvaluationEngine` — an internal implementation
detail of `basis_core.evaluation`. A downstream consumer that only imports
`basis_core.enforcement` and `basis_core.policy` had no compliant way to
construct it. `for_bundle()` closes that gap by constructing the internal
engine on the caller's behalf.

This file proves the public factory's contract specifically. It does not
retest enforcement-point evaluation semantics (disposition mapping,
fail-closed containment, caller-supplied facts, determinism, immutability)
— `test_operation_aware_enforcement_point.py` already owns that exhaustively.
Every test here that needs a real evaluation asserts *equivalence* to a
directly-constructed enforcement point, not a second copy of those semantics.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

# Deliberately the only imports used to build and exercise the factory-created
# enforcement point below — this is the public downstream contract itself.
from basis_core.decisions import OperationAwareDecisionRequest
from basis_core.enforcement import OperationAwareEnforcementPoint
from basis_core.policy import PolicyBundle

_SUBJECT_ID = "svc-public-factory-test"
_RECORDED_AT = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)


# ══════════════════════════════════════════════════════════════════════════
# Construction helpers — public models only, mirroring the conventions in
# test_operation_aware_enforcement_point.py without importing anything internal.
# ══════════════════════════════════════════════════════════════════════════


def _build_request(**overrides: object) -> OperationAwareDecisionRequest:
    kwargs: dict[str, object] = {
        "request_id": "req-public-factory-0001",
        "correlation_id": "corr-public-factory-0001",
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
) -> dict[str, object]:
    return {"rule_id": rule_id, "effect": effect, "match": {"actions": [action]}}


def _build_bundle(
    rules: list[dict[str, object]] | None = None,
    *,
    bundle_id: str = "bundle-public-factory-fixture",
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


# ══════════════════════════════════════════════════════════════════════════
# 1. Construction
# ══════════════════════════════════════════════════════════════════════════


class TestFactoryConstruction:
    def test_for_bundle_returns_enforcement_point(self) -> None:
        bundle = _build_bundle()
        ep = OperationAwareEnforcementPoint.for_bundle(bundle)
        assert isinstance(ep, OperationAwareEnforcementPoint)

    def test_hasattr_for_bundle(self) -> None:
        assert hasattr(OperationAwareEnforcementPoint, "for_bundle")

    def test_for_bundle_is_a_classmethod(self) -> None:
        # Callable directly on the class, without an instance.
        bundle = _build_bundle()
        assert callable(OperationAwareEnforcementPoint.for_bundle)
        ep = OperationAwareEnforcementPoint.for_bundle(bundle)
        assert ep is not None


# ══════════════════════════════════════════════════════════════════════════
# 2. Real evaluation through the factory-created enforcement point
# ══════════════════════════════════════════════════════════════════════════


class TestFactoryRealEvaluation:
    def test_allow_outcome(self) -> None:
        bundle = _build_bundle(rules=[_rule_dict("allow-rule", effect="allow", action="read:ahu")])
        ep = OperationAwareEnforcementPoint.for_bundle(bundle)
        result = ep.evaluate(
            request=_build_request(action="read:ahu"),
            trace_id="trace-factory-allow-1",
            evidence_id="evidence-factory-allow-1",
            recorded_at=_RECORDED_AT,
        )
        assert result.response.outcome is not None
        assert result.response.outcome.value == "allow"
        assert result.disposition.value == "allow"

    def test_explicit_deny_outcome(self) -> None:
        bundle = _build_bundle(
            rules=[
                _rule_dict("allow-rule", effect="allow", action="read:ahu"),
                _rule_dict("deny-rule", effect="deny", action="read:ahu"),
            ]
        )
        ep = OperationAwareEnforcementPoint.for_bundle(bundle)
        result = ep.evaluate(
            request=_build_request(action="read:ahu"),
            trace_id="trace-factory-deny-1",
            evidence_id="evidence-factory-deny-1",
            recorded_at=_RECORDED_AT,
        )
        assert result.response.outcome is not None
        assert result.response.outcome.value == "deny"
        assert result.disposition.value == "deny"

    def test_not_applicable_outcome(self) -> None:
        bundle = _build_bundle(scope={"actions": ["write:ahu"]})
        ep = OperationAwareEnforcementPoint.for_bundle(bundle)
        result = ep.evaluate(
            request=_build_request(action="read:ahu"),
            trace_id="trace-factory-na-1",
            evidence_id="evidence-factory-na-1",
            recorded_at=_RECORDED_AT,
        )
        assert result.response.outcome is not None
        assert result.response.outcome.value == "not_applicable"
        # NOT_APPLICABLE still collapses to a deny disposition (enforcement-only
        # vocabulary), matching the documented, unchanged disposition mapping.
        assert result.disposition.value == "deny"

    def test_audit_evidence_is_produced(self) -> None:
        bundle = _build_bundle(rules=[_rule_dict("allow-rule", effect="allow", action="read:ahu")])
        ep = OperationAwareEnforcementPoint.for_bundle(bundle)
        result = ep.evaluate(
            request=_build_request(action="read:ahu"),
            trace_id="trace-factory-evidence-1",
            evidence_id="evidence-factory-evidence-1",
            recorded_at=_RECORDED_AT,
        )
        assert result.audit_evidence is not None
        assert result.audit_evidence.evidence_id == "evidence-factory-evidence-1"

    def test_never_raises_on_governed_failure(self) -> None:
        """A duplicate rule_id bundle is a governed `policy_validation_failure`
        — the factory-created enforcement point must handle it the same
        fail-closed way as a directly-constructed one (no exception)."""
        bundle = _build_bundle(
            rules=[
                _rule_dict("dup-rule", effect="allow", action="read:ahu"),
                _rule_dict("dup-rule", effect="deny", action="write:ahu"),
            ]
        )
        ep = OperationAwareEnforcementPoint.for_bundle(bundle)
        result = ep.evaluate(
            request=_build_request(),
            trace_id="trace-factory-pvf-1",
            evidence_id="evidence-factory-pvf-1",
            recorded_at=_RECORDED_AT,
        )
        assert result.response.evaluation_status.value == "failed"
        assert result.response.outcome is None
        assert result.disposition.value == "deny"


# ══════════════════════════════════════════════════════════════════════════
# 3. Direct-constructor equivalence
# ══════════════════════════════════════════════════════════════════════════


class TestDirectConstructorEquivalence:
    """Construct one enforcement point through the existing internal/direct
    path (importing the internal engine only inside this test module, never
    inside the public-factory code path itself) and one through the public
    factory; evaluate the same request against the same bundle and compare
    governed output fields."""

    def _direct_enforcement_point(self, bundle: PolicyBundle) -> OperationAwareEnforcementPoint:
        # Imported locally, and only for this equivalence check — the public
        # factory test above never imports this.
        from basis_core.evaluation.operation_aware.engine import (
            OperationAwareEvaluationEngine,
        )

        return OperationAwareEnforcementPoint(
            engine=OperationAwareEvaluationEngine(), bundle=bundle
        )

    @pytest.mark.parametrize(
        "rules,scope,action",
        [
            ([_rule_dict("allow-rule", effect="allow", action="read:ahu")], None, "read:ahu"),
            (
                [
                    _rule_dict("allow-rule", effect="allow", action="read:ahu"),
                    _rule_dict("deny-rule", effect="deny", action="read:ahu"),
                ],
                None,
                "read:ahu",
            ),
            ([_rule_dict("allow-rule", effect="allow", action="write:ahu")], None, "read:ahu"),
            (None, {"actions": ["write:ahu"]}, "read:ahu"),
        ],
        ids=["allow", "explicit-deny", "default-deny", "not-applicable"],
    )
    def test_governed_output_fields_match(
        self,
        rules: list[dict[str, object]] | None,
        scope: dict[str, object] | None,
        action: str,
    ) -> None:
        bundle_kwargs: dict[str, object] = {}
        if rules is not None:
            bundle_kwargs["rules"] = rules
        if scope is not None:
            bundle_kwargs["scope"] = scope
        bundle = _build_bundle(**bundle_kwargs)  # type: ignore[arg-type]
        request = _build_request(action=action)

        direct_ep = self._direct_enforcement_point(bundle)
        factory_ep = OperationAwareEnforcementPoint.for_bundle(bundle)

        # Same trace_id/evidence_id/recorded_at supplied to both — only the
        # construction path differs.
        direct_result = direct_ep.evaluate(
            request=request,
            trace_id="trace-equivalence-1",
            evidence_id="evidence-equivalence-1",
            recorded_at=_RECORDED_AT,
        )
        factory_result = factory_ep.evaluate(
            request=request,
            trace_id="trace-equivalence-1",
            evidence_id="evidence-equivalence-1",
            recorded_at=_RECORDED_AT,
        )

        # Governed output fields — identical inputs (including identical
        # caller-supplied trace_id/evidence_id/recorded_at) must produce
        # identical results end to end.
        assert direct_result.response.evaluation_status == factory_result.response.evaluation_status
        assert direct_result.response.outcome == factory_result.response.outcome
        assert direct_result.response.failure_reason == factory_result.response.failure_reason
        assert direct_result.disposition == factory_result.disposition
        assert direct_result.response.reason_code == factory_result.response.reason_code

        if direct_result.response.evaluation_trace is not None:
            direct_rule_ids = [
                e.rule_id for e in direct_result.response.evaluation_trace.rule_evidence
            ]
        else:
            direct_rule_ids = None
        if factory_result.response.evaluation_trace is not None:
            factory_rule_ids = [
                e.rule_id for e in factory_result.response.evaluation_trace.rule_evidence
            ]
        else:
            factory_rule_ids = None
        assert direct_rule_ids == factory_rule_ids

        # Audit evidence semantics: both present or both absent, and equal
        # in every field except caller-supplied identifiers are identical
        # anyway (same trace_id/evidence_id/recorded_at supplied to both).
        assert (direct_result.audit_evidence is None) == (factory_result.audit_evidence is None)
        if direct_result.audit_evidence is not None and factory_result.audit_evidence is not None:
            assert direct_result.audit_evidence == factory_result.audit_evidence

        # The full response is identical when trace embedding is off for
        # both (default) — request_id/correlation_id/bundle identity are
        # all caller/bundle-supplied facts, not construction-path facts.
        assert direct_result.response == factory_result.response


# ══════════════════════════════════════════════════════════════════════════
# 4. Independent engines
# ══════════════════════════════════════════════════════════════════════════


class TestIndependentEngines:
    def test_two_factory_calls_produce_distinct_enforcement_points(self) -> None:
        bundle = _build_bundle()
        ep1 = OperationAwareEnforcementPoint.for_bundle(bundle)
        ep2 = OperationAwareEnforcementPoint.for_bundle(bundle)
        assert ep1 is not ep2

    def test_two_factory_calls_do_not_share_mutable_state(self) -> None:
        """Behavioral proof of independence: evaluate through one, then the
        other, then the first again — results must be stable/deterministic,
        proving no shared mutable evaluator state leaks between instances."""
        bundle = _build_bundle(rules=[_rule_dict("allow-rule", effect="allow", action="read:ahu")])
        ep1 = OperationAwareEnforcementPoint.for_bundle(bundle)
        ep2 = OperationAwareEnforcementPoint.for_bundle(bundle)
        request = _build_request(action="read:ahu")

        result1a = ep1.evaluate(
            request=request,
            trace_id="trace-independent-1",
            evidence_id="evidence-independent-1",
            recorded_at=_RECORDED_AT,
        )
        result2 = ep2.evaluate(
            request=request,
            trace_id="trace-independent-1",
            evidence_id="evidence-independent-1",
            recorded_at=_RECORDED_AT,
        )
        result1b = ep1.evaluate(
            request=request,
            trace_id="trace-independent-1",
            evidence_id="evidence-independent-1",
            recorded_at=_RECORDED_AT,
        )
        assert result1a == result1b
        assert result1a == result2


# ══════════════════════════════════════════════════════════════════════════
# 5. Bundle preservation
# ══════════════════════════════════════════════════════════════════════════


class TestBundlePreservation:
    def test_bundle_is_not_mutated_by_construction(self) -> None:
        bundle = _build_bundle()
        snapshot = bundle.model_dump()
        OperationAwareEnforcementPoint.for_bundle(bundle)
        assert bundle.model_dump() == snapshot

    def test_bundle_is_not_mutated_by_evaluation(self) -> None:
        bundle = _build_bundle(rules=[_rule_dict("allow-rule", effect="allow", action="read:ahu")])
        snapshot = bundle.model_dump()
        ep = OperationAwareEnforcementPoint.for_bundle(bundle)
        ep.evaluate(
            request=_build_request(action="read:ahu"),
            trace_id="trace-bundle-preservation-1",
            evidence_id="evidence-bundle-preservation-1",
            recorded_at=_RECORDED_AT,
        )
        assert bundle.model_dump() == snapshot


# ══════════════════════════════════════════════════════════════════════════
# 6. Invalid argument behavior — current Pydantic/runtime behavior only
# ══════════════════════════════════════════════════════════════════════════


class TestInvalidArgument:
    def test_non_policy_bundle_value_fails(self) -> None:
        """No handwritten validation layer is introduced by `for_bundle()` —
        it accepts whatever `__init__` already accepts. A plain dict is not
        a `PolicyBundle` instance and must fail clearly and immediately when
        the enforcement point actually tries to use it as one, exactly as
        direct construction with a non-`PolicyBundle` already does today
        (see `test_operation_aware_enforcement_point.py`'s own
        `# type: ignore[arg-type]` construction-time uses of a plain dict,
        which likewise defer failure to evaluate()-time attribute access)."""
        not_a_bundle = {"bundle_id": "not-a-real-bundle"}
        ep = OperationAwareEnforcementPoint.for_bundle(not_a_bundle)  # type: ignore[arg-type]
        with pytest.raises(AttributeError):
            ep.evaluate(
                request=_build_request(),
                trace_id="trace-invalid-1",
                evidence_id="evidence-invalid-1",
                recorded_at=_RECORDED_AT,
            )

    def test_none_bundle_fails(self) -> None:
        ep = OperationAwareEnforcementPoint.for_bundle(None)  # type: ignore[arg-type]
        with pytest.raises(AttributeError):
            ep.evaluate(
                request=_build_request(),
                trace_id="trace-invalid-2",
                evidence_id="evidence-invalid-2",
                recorded_at=_RECORDED_AT,
            )
