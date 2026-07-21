"""
tests/operation_aware/test_policy_aggregation.py — tests for
`basis_core.policy.operation_aware.aggregation` (Milestone 9, PR 27 of
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`: "Effect
aggregation and final-outcome semantics (policy-owned)").

Covers the full aggregation truth table — evaluation status, authorization
outcome, failure reason, and final reason code: `not_applicable` handling,
evaluation-failure handling (including the governed
`OperationAwareFailureReason.CONDITION_EVALUATION_ERROR` category), deny
precedence, allow determination, default deny, deterministic reason
selection, and v0.1.0/`PolicyEngine` compatibility.

`failure_reason` vs. `reason_code`
───────────────────────────────────
These are two distinct fields tested independently throughout this file,
per the module's own docstring: `failure_reason` is the governed evaluator
failure *category* (`OperationAwareFailureReason`, non-`None` only when
`status` is `FAILED`); `reason_code` is the machine-readable authorization
*explanation* (`ReasonCode`, non-`None` only when `status` is `COMPLETED`).
Neither field is ever used as a stand-in for the other, and this file
never asserts one where the other is meant.

Vocabulary ownership (PR 27A)
──────────────────────────────
`OperationAwareFailureReason` is owned by `basis_core.decisions.
operation_aware` — a shared operation-aware evaluation-result vocabulary,
not a policy-owned type. This file imports it directly from
`basis_core.decisions.operation_aware`, the same source
`basis_core.policy.operation_aware.aggregation` itself imports (and
re-exposes only by virtue of that import, not by defining a second copy)
— see `test_failure_reason_type_is_defined_in_decisions_operation_aware`,
`test_aggregation_uses_the_decisions_owned_failure_reason_type`, and
`test_aggregation_module_does_not_define_its_own_failure_reason_enum`
below, and `aggregation.py`'s own docstring, "Import boundary and
vocabulary ownership", for the full rationale.

Scope
─────
This file tests `aggregate_policy_outcome` and its typed inputs/outputs
only. It does not test, and must never test: bundle applicability
determination (`test_applicability.py` owns that), selector matching
(`test_selector.py`), condition evaluation (`test_operators.py`,
`test_condition_eval.py`), trace assembly (`test_trace_assembly.py`), or
any future `OperationAwareEvaluationEngine` orchestration (PR 27B,
separately-scoped roadmap work) — this module's inputs are always
hand-constructed `EvaluatedRule` facts, never derived from a real bundle or
request. It also does not test — and must never test — any
`OperationAwareFailureReason` member other than
`CONDITION_EVALUATION_ERROR`: this module never constructs the other five
(see `aggregation.py`'s docstring, "Scope boundary"), so there is nothing
to assert about them here.
"""

from __future__ import annotations

import itertools
from pathlib import Path

import pytest

from basis_core.decisions.operation_aware import OperationAwareFailureReason
from basis_core.policy.operation_aware.aggregation import (
    EvaluatedRule,
    OperationAwarePolicyOutcome,
    PolicyAggregationInputError,
    PolicyAggregationResult,
    PolicyAggregationStatus,
    aggregate_policy_outcome,
)
from basis_core.policy.operation_aware.applicability import ApplicabilityResult
from basis_core.policy.operation_aware.condition_eval import RuleConditionResult
from basis_core.policy.operation_aware.rule import RuleEffect

# ══════════════════════════════════════════════════════════════════════════
# Construction helpers
# ══════════════════════════════════════════════════════════════════════════


def _matched_allow(rule_id: str = "rule-allow") -> EvaluatedRule:
    return EvaluatedRule(
        rule_id=rule_id, effect=RuleEffect.ALLOW, result=RuleConditionResult.MATCHED
    )


def _matched_deny(rule_id: str = "rule-deny") -> EvaluatedRule:
    return EvaluatedRule(
        rule_id=rule_id, effect=RuleEffect.DENY, result=RuleConditionResult.MATCHED
    )


def _not_matched(rule_id: str, effect: RuleEffect) -> EvaluatedRule:
    return EvaluatedRule(rule_id=rule_id, effect=effect, result=RuleConditionResult.NOT_MATCHED)


def _errored(rule_id: str = "rule-error", effect: RuleEffect = RuleEffect.DENY) -> EvaluatedRule:
    return EvaluatedRule(rule_id=rule_id, effect=effect, result=RuleConditionResult.ERROR)


# ══════════════════════════════════════════════════════════════════════════
# Non-applicable
# ══════════════════════════════════════════════════════════════════════════


def test_not_applicable_bundle_produces_not_applicable_outcome() -> None:
    result = aggregate_policy_outcome(ApplicabilityResult.NOT_APPLICABLE, [])
    assert result.status is PolicyAggregationStatus.COMPLETED
    assert result.outcome is OperationAwarePolicyOutcome.NOT_APPLICABLE
    assert result.failure_reason is None
    assert result.reason_code == "no_applicable_bundle"


def test_not_applicable_remains_distinct_from_deny() -> None:
    not_applicable = aggregate_policy_outcome(ApplicabilityResult.NOT_APPLICABLE, [])
    default_deny = aggregate_policy_outcome(ApplicabilityResult.APPLICABLE, [])
    assert not_applicable.outcome is OperationAwarePolicyOutcome.NOT_APPLICABLE
    assert default_deny.outcome is OperationAwarePolicyOutcome.DENY
    assert not_applicable.outcome != default_deny.outcome
    assert not_applicable.reason_code != default_deny.reason_code


def test_not_applicable_with_evaluated_rule_contributions_is_rejected() -> None:
    with pytest.raises(PolicyAggregationInputError):
        aggregate_policy_outcome(ApplicabilityResult.NOT_APPLICABLE, [_matched_allow()])


def test_not_applicable_with_only_a_not_matched_rule_contribution_is_still_rejected() -> None:
    """Even a single non-matching rule contribution is inconsistent with
    `not_applicable`: a non-applicable bundle has no candidate rules at
    all, matched or not."""
    with pytest.raises(PolicyAggregationInputError):
        aggregate_policy_outcome(
            ApplicabilityResult.NOT_APPLICABLE, [_not_matched("r1", RuleEffect.ALLOW)]
        )


# ══════════════════════════════════════════════════════════════════════════
# Failure
# ══════════════════════════════════════════════════════════════════════════


def test_one_rule_error_produces_evaluation_failure_with_no_authorization_outcome() -> None:
    result = aggregate_policy_outcome(ApplicabilityResult.APPLICABLE, [_errored()])
    assert result.status is PolicyAggregationStatus.FAILED
    assert result.outcome is None
    assert result.reason_code is None


def test_one_rule_error_produces_condition_evaluation_error_failure_reason() -> None:
    """Required test 6: a single errored rule produces the governed
    `condition_evaluation_error` failure category — the only failure
    category this module can determine from its own inputs."""
    result = aggregate_policy_outcome(ApplicabilityResult.APPLICABLE, [_errored()])
    assert result.status is PolicyAggregationStatus.FAILED
    assert result.failure_reason is OperationAwareFailureReason.CONDITION_EVALUATION_ERROR


def test_failed_result_requires_a_non_null_failure_reason() -> None:
    """Required test 1."""
    with pytest.raises(ValueError):
        PolicyAggregationResult(
            status=PolicyAggregationStatus.FAILED,
            outcome=None,
            failure_reason=None,
            reason_code=None,
        )


def test_completed_result_rejects_a_non_null_failure_reason() -> None:
    """Required test 2."""
    with pytest.raises(ValueError):
        PolicyAggregationResult(
            status=PolicyAggregationStatus.COMPLETED,
            outcome=OperationAwarePolicyOutcome.ALLOW,
            failure_reason=OperationAwareFailureReason.CONDITION_EVALUATION_ERROR,
            reason_code="allow_rule_matched",  # type: ignore[arg-type]
        )


def test_failure_is_not_rewritten_to_deny() -> None:
    result = aggregate_policy_outcome(
        ApplicabilityResult.APPLICABLE, [_errored(effect=RuleEffect.DENY)]
    )
    assert result.outcome is not OperationAwarePolicyOutcome.DENY
    assert result.outcome is None
    assert result.failure_reason is OperationAwareFailureReason.CONDITION_EVALUATION_ERROR


def test_failure_behavior_is_deterministic() -> None:
    rules = [_matched_allow(), _errored()]
    first = aggregate_policy_outcome(ApplicabilityResult.APPLICABLE, rules)
    second = aggregate_policy_outcome(ApplicabilityResult.APPLICABLE, rules)
    assert first == second
    assert first.status is PolicyAggregationStatus.FAILED
    assert first.failure_reason is OperationAwareFailureReason.CONDITION_EVALUATION_ERROR


@pytest.mark.parametrize(
    "rules",
    [
        [_matched_allow(), _matched_deny(), _errored("rule-error")],
        [_errored("rule-error"), _matched_allow(), _matched_deny()],
        [_matched_deny(), _errored("rule-error"), _matched_allow()],
    ],
)
def test_mixed_matched_rules_plus_evaluator_error_follows_failure_semantics(
    rules: list[EvaluatedRule],
) -> None:
    """Required tests 7-8: a matched DENY and a matched ALLOW are both
    present alongside an errored rule; failure dominates deny precedence
    and allow determination unconditionally, and the failure category is
    the same regardless of the errored rule's position in the supplied
    sequence."""
    result = aggregate_policy_outcome(ApplicabilityResult.APPLICABLE, rules)
    assert result.status is PolicyAggregationStatus.FAILED
    assert result.outcome is None
    assert result.reason_code is None
    assert result.failure_reason is OperationAwareFailureReason.CONDITION_EVALUATION_ERROR


def test_rule_ordering_does_not_change_the_failure_category() -> None:
    """Required test 8 (explicit permutation form): every ordering of a
    fixed multiset containing an errored rule produces the identical
    failure result, including `failure_reason`."""
    base_rules = [_matched_allow("a1"), _errored("rule-error"), _matched_deny("d1")]
    results = {
        aggregate_policy_outcome(ApplicabilityResult.APPLICABLE, list(ordering))
        for ordering in itertools.permutations(base_rules)
    }
    assert results == {
        PolicyAggregationResult(
            status=PolicyAggregationStatus.FAILED,
            outcome=None,
            failure_reason=OperationAwareFailureReason.CONDITION_EVALUATION_ERROR,
            reason_code=None,
        )
    }


# ══════════════════════════════════════════════════════════════════════════
# Deny precedence
# ══════════════════════════════════════════════════════════════════════════


def test_one_matched_deny_produces_deny() -> None:
    result = aggregate_policy_outcome(ApplicabilityResult.APPLICABLE, [_matched_deny()])
    assert result.outcome is OperationAwarePolicyOutcome.DENY
    assert result.failure_reason is None
    assert result.reason_code == "deny_rule_matched"


def test_matched_allow_followed_by_matched_deny_produces_deny() -> None:
    result = aggregate_policy_outcome(
        ApplicabilityResult.APPLICABLE, [_matched_allow(), _matched_deny()]
    )
    assert result.outcome is OperationAwarePolicyOutcome.DENY
    assert result.reason_code == "deny_rule_matched"


def test_matched_deny_followed_by_matched_allow_produces_deny() -> None:
    result = aggregate_policy_outcome(
        ApplicabilityResult.APPLICABLE, [_matched_deny(), _matched_allow()]
    )
    assert result.outcome is OperationAwarePolicyOutcome.DENY
    assert result.reason_code == "deny_rule_matched"


def test_multiple_matched_allows_plus_one_matched_deny_produce_deny() -> None:
    result = aggregate_policy_outcome(
        ApplicabilityResult.APPLICABLE,
        [_matched_allow("a1"), _matched_allow("a2"), _matched_deny(), _matched_allow("a3")],
    )
    assert result.outcome is OperationAwarePolicyOutcome.DENY
    assert result.reason_code == "deny_rule_matched"


def test_reordering_allow_and_deny_facts_does_not_change_final_outcome() -> None:
    base_rules = [_matched_allow("a1"), _matched_deny("d1"), _matched_allow("a2")]
    results = {
        aggregate_policy_outcome(ApplicabilityResult.APPLICABLE, list(ordering))
        for ordering in itertools.permutations(base_rules)
    }
    assert results == {
        PolicyAggregationResult(
            status=PolicyAggregationStatus.COMPLETED,
            outcome=OperationAwarePolicyOutcome.DENY,
            failure_reason=None,
            reason_code="deny_rule_matched",  # type: ignore[arg-type]
        )
    }


# ══════════════════════════════════════════════════════════════════════════
# Allow
# ══════════════════════════════════════════════════════════════════════════


def test_one_matched_allow_with_no_deny_produces_allow() -> None:
    result = aggregate_policy_outcome(ApplicabilityResult.APPLICABLE, [_matched_allow()])
    assert result.outcome is OperationAwarePolicyOutcome.ALLOW
    assert result.failure_reason is None
    assert result.reason_code == "allow_rule_matched"


def test_multiple_matched_allows_with_no_deny_produce_allow() -> None:
    result = aggregate_policy_outcome(
        ApplicabilityResult.APPLICABLE, [_matched_allow("a1"), _matched_allow("a2")]
    )
    assert result.outcome is OperationAwarePolicyOutcome.ALLOW
    assert result.reason_code == "allow_rule_matched"


def test_nonmatching_deny_rules_do_not_override_a_matched_allow() -> None:
    result = aggregate_policy_outcome(
        ApplicabilityResult.APPLICABLE,
        [_matched_allow(), _not_matched("deny-candidate", RuleEffect.DENY)],
    )
    assert result.outcome is OperationAwarePolicyOutcome.ALLOW
    assert result.reason_code == "allow_rule_matched"


# ══════════════════════════════════════════════════════════════════════════
# Default deny
# ══════════════════════════════════════════════════════════════════════════


def test_zero_matched_rules_produce_deny() -> None:
    result = aggregate_policy_outcome(ApplicabilityResult.APPLICABLE, [])
    assert result.outcome is OperationAwarePolicyOutcome.DENY
    assert result.failure_reason is None
    assert result.reason_code == "no_allow_rule_matched"


def test_only_nonmatching_rules_produce_deny() -> None:
    result = aggregate_policy_outcome(
        ApplicabilityResult.APPLICABLE,
        [_not_matched("a1", RuleEffect.ALLOW), _not_matched("d1", RuleEffect.DENY)],
    )
    assert result.outcome is OperationAwarePolicyOutcome.DENY
    assert result.reason_code == "no_allow_rule_matched"


def test_default_deny_has_a_different_reason_from_explicit_deny_precedence() -> None:
    default_deny = aggregate_policy_outcome(ApplicabilityResult.APPLICABLE, [])
    explicit_deny = aggregate_policy_outcome(ApplicabilityResult.APPLICABLE, [_matched_deny()])
    assert default_deny.outcome is explicit_deny.outcome is OperationAwarePolicyOutcome.DENY
    assert default_deny.reason_code != explicit_deny.reason_code
    assert default_deny.reason_code == "no_allow_rule_matched"
    assert explicit_deny.reason_code == "deny_rule_matched"


# ══════════════════════════════════════════════════════════════════════════
# Determinism
# ══════════════════════════════════════════════════════════════════════════


def test_identical_typed_inputs_produce_equal_outputs() -> None:
    """Required test 9 (completed case)."""
    rules = [_matched_allow("a1"), _not_matched("d1", RuleEffect.DENY)]
    first = aggregate_policy_outcome(ApplicabilityResult.APPLICABLE, list(rules))
    second = aggregate_policy_outcome(ApplicabilityResult.APPLICABLE, list(rules))
    assert first == second


def test_identical_inputs_produce_an_equal_result_including_failure_reason() -> None:
    """Required test 9 (failed case) — equality must hold across all four
    fields, `failure_reason` included."""
    rules = [_errored("rule-error")]
    first = aggregate_policy_outcome(ApplicabilityResult.APPLICABLE, list(rules))
    second = aggregate_policy_outcome(ApplicabilityResult.APPLICABLE, list(rules))
    assert first == second
    assert (
        first.failure_reason
        == second.failure_reason
        == (OperationAwareFailureReason.CONDITION_EVALUATION_ERROR)
    )


def test_no_dependence_on_supplied_sequence_type() -> None:
    """A tuple and a list carrying the same facts in the same order must
    produce equal results — no list/iteration-order-specific behavior."""
    rules = (_matched_allow("a1"), _matched_deny("d1"))
    as_list = aggregate_policy_outcome(ApplicabilityResult.APPLICABLE, list(rules))
    as_tuple = aggregate_policy_outcome(ApplicabilityResult.APPLICABLE, rules)
    assert as_list == as_tuple


def test_supplied_order_does_not_define_deny_precedence() -> None:
    """Every permutation of a fixed multiset of facts must resolve to the
    same aggregation result — order is evidence order, never authorization
    precedence."""
    base_rules = [
        _not_matched("a0", RuleEffect.ALLOW),
        _matched_allow("a1"),
        _not_matched("d0", RuleEffect.DENY),
    ]
    results = {
        aggregate_policy_outcome(ApplicabilityResult.APPLICABLE, list(ordering))
        for ordering in itertools.permutations(base_rules)
    }
    assert len(results) == 1
    (only_result,) = results
    assert only_result.outcome is OperationAwarePolicyOutcome.ALLOW


def test_repeated_calls_with_equal_inputs_are_equal_no_hidden_state() -> None:
    calls = [
        aggregate_policy_outcome(ApplicabilityResult.APPLICABLE, [_matched_deny()])
        for _ in range(5)
    ]
    assert len(set(calls)) == 1


# ══════════════════════════════════════════════════════════════════════════
# PolicyAggregationResult construction invariant
# ══════════════════════════════════════════════════════════════════════════


def test_result_rejects_failed_status_with_a_non_none_outcome() -> None:
    """Required test 3."""
    with pytest.raises(ValueError):
        PolicyAggregationResult(
            status=PolicyAggregationStatus.FAILED,
            outcome=OperationAwarePolicyOutcome.DENY,
            failure_reason=OperationAwareFailureReason.CONDITION_EVALUATION_ERROR,
            reason_code=None,
        )


def test_result_rejects_failed_status_with_a_non_none_reason_code() -> None:
    """Required test 4."""
    with pytest.raises(ValueError):
        PolicyAggregationResult(
            status=PolicyAggregationStatus.FAILED,
            outcome=None,
            failure_reason=OperationAwareFailureReason.CONDITION_EVALUATION_ERROR,
            reason_code="deny_rule_matched",  # type: ignore[arg-type]
        )


def test_result_rejects_completed_status_with_a_none_outcome() -> None:
    """Required test 5 (outcome half)."""
    with pytest.raises(ValueError):
        PolicyAggregationResult(
            status=PolicyAggregationStatus.COMPLETED,
            outcome=None,
            failure_reason=None,
            reason_code="deny_rule_matched",  # type: ignore[arg-type]
        )


def test_result_rejects_completed_status_with_a_none_reason_code() -> None:
    """Required test 5 (reason_code half)."""
    with pytest.raises(ValueError):
        PolicyAggregationResult(
            status=PolicyAggregationStatus.COMPLETED,
            outcome=OperationAwarePolicyOutcome.DENY,
            failure_reason=None,
            reason_code=None,
        )


# ══════════════════════════════════════════════════════════════════════════
# Vocabulary ownership (PR 27A) — decisions owns it, policy reuses it
# ══════════════════════════════════════════════════════════════════════════


def test_failure_reason_type_is_defined_in_decisions_operation_aware() -> None:
    """Required test 1: `OperationAwareFailureReason` is defined in
    `basis_core.decisions.operation_aware`, not in `policy/`."""
    assert OperationAwareFailureReason.__module__ == "basis_core.decisions.operation_aware"


def test_aggregation_uses_the_decisions_owned_failure_reason_type() -> None:
    """Required test 2: `aggregation.py` imports and uses the exact same
    `OperationAwareFailureReason` object defined in `decisions.
    operation_aware` — not a structurally-similar but separately-defined
    type. Both the module-level attribute and the type actually attached
    to a real failure result are checked."""
    from basis_core.decisions.operation_aware import (
        OperationAwareFailureReason as decisions_failure_reason,
    )
    from basis_core.policy.operation_aware import aggregation as aggregation_module

    assert aggregation_module.OperationAwareFailureReason is decisions_failure_reason

    result = aggregate_policy_outcome(ApplicabilityResult.APPLICABLE, [_errored()])
    assert result.failure_reason is not None
    assert type(result.failure_reason) is decisions_failure_reason


def test_aggregation_module_does_not_define_its_own_failure_reason_enum() -> None:
    """Required test 3: policy does not define a second failure-reason
    enum. Statically confirms `aggregation.py`'s own source contains no
    `class OperationAwareFailureReason` definition — the name may appear
    only as an imported reference."""
    import ast
    import inspect

    from basis_core.policy.operation_aware import aggregation as aggregation_module

    source = inspect.getsource(aggregation_module)
    tree = ast.parse(source)
    class_defs = [node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
    assert "OperationAwareFailureReason" not in class_defs


def test_aggregation_module_does_not_import_audit_or_evaluation() -> None:
    """Required test 4: statically confirms `aggregation.py` never imports
    `basis_core.audit` or `basis_core.evaluation`, even though the failure
    vocabulary it now imports (from `decisions/`) carries the same values
    as an audit-owned type. This complements (does not replace) the
    recursive package-wide guard in `tests/test_import_boundaries.py::
    test_policy_operation_aware_does_not_import_a_forbidden_layer`."""
    import ast
    import inspect

    from basis_core.policy.operation_aware import aggregation as aggregation_module

    source = inspect.getsource(aggregation_module)
    tree = ast.parse(source)
    imported_modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported_modules.append(node.module)
        elif isinstance(node, ast.Import):
            imported_modules.extend(alias.name for alias in node.names)

    assert not any(m.startswith("basis_core.audit") for m in imported_modules)
    assert not any(m.startswith("basis_core.evaluation") for m in imported_modules)


def test_decision_and_trace_failure_vocabularies_have_exact_name_and_value_parity() -> None:
    """Required test 5: the decisions-owned `OperationAwareFailureReason`
    and the audit-owned `TraceFailureReason` (`audit/operation_aware/
    evaluation_trace.py`, unmoved, unchanged — see "Audit separation" in
    `decisions/operation_aware.py`'s docstring) have exactly equal member
    *names* and *string values* — no new failure vocabulary was invented,
    and neither type diverges from the other."""
    from basis_core.audit.operation_aware.evaluation_trace import TraceFailureReason

    assert {member.name for member in OperationAwareFailureReason} == {
        member.name for member in TraceFailureReason
    }
    assert {member.value for member in OperationAwareFailureReason} == {
        member.value for member in TraceFailureReason
    }
    assert (
        OperationAwareFailureReason.CONDITION_EVALUATION_ERROR.value
        == TraceFailureReason.CONDITION_EVALUATION_ERROR.value
        == "condition_evaluation_error"
    )
    # Audit is not moved, removed, or made to depend on policy by this PR.
    assert TraceFailureReason.__module__ == "basis_core.audit.operation_aware.evaluation_trace"


def test_this_module_still_does_not_define_the_orchestration_engine_itself() -> None:
    """Required test 8, updated for PR 27B: this module (PR 27A's policy-owned
    aggregation) never defined, and still does not define,
    `OperationAwareEvaluationEngine` — that orchestration class now legitimately
    exists (`src/basis_core/evaluation/operation_aware/engine.py`, PR 27B), but
    it lives in `evaluation/`, not here, and this module was never its owner.
    This test originally asserted the engine module did not exist at all,
    back when PR 27A's own scope was "moving the failure vocabulary to
    `decisions/` does not, by itself, imply or require any orchestration
    code" — that assertion is now obsolete by design, since PR 27B's entire
    purpose is to add that orchestration code. What remains true, and what
    this test now checks instead, is that `aggregation.py` itself was never
    the engine's home and does not define it."""
    import ast
    import inspect

    from basis_core.policy.operation_aware import aggregation as aggregation_module

    source = inspect.getsource(aggregation_module)
    tree = ast.parse(source)
    class_defs = [node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
    assert "OperationAwareEvaluationEngine" not in class_defs
    assert "OperationAwarePolicyEngine" not in class_defs


# ══════════════════════════════════════════════════════════════════════════
# Compatibility with v0.1.0
# ══════════════════════════════════════════════════════════════════════════


def test_constructing_or_invoking_aggregation_has_no_observable_effect_on_policy_engine() -> None:
    """Regression check (roadmap PR 27's required compatibility test):
    building/calling this module's types must not share mutable state with,
    or otherwise change the behavior of, an existing v0.1.0 `PolicyEngine`
    instance."""
    from basis_core.domain.subject import Subject
    from basis_core.policy.engine import PolicyEngine
    from basis_core.policy.engine import PolicyOutcome as V01PolicyOutcome
    from basis_core.policy.rules import RolePolicyRule

    role_table = {"read:ahu": {"operator"}}
    engine = PolicyEngine(policies=[RolePolicyRule(role_table)])
    subject = Subject(id="sub-1", name="Test Subject", roles=["operator"])

    before = engine.evaluate(subject, "read:ahu")
    assert before.outcome is V01PolicyOutcome.ALLOW

    # Exercise the operation-aware aggregation module in between, including
    # its failure path.
    aggregate_policy_outcome(ApplicabilityResult.APPLICABLE, [_matched_deny()])
    aggregate_policy_outcome(ApplicabilityResult.NOT_APPLICABLE, [])
    aggregate_policy_outcome(ApplicabilityResult.APPLICABLE, [_errored()])
    for _ in range(3):
        aggregate_policy_outcome(ApplicabilityResult.APPLICABLE, [_matched_allow()])

    after = engine.evaluate(subject, "read:ahu")
    assert after.outcome is V01PolicyOutcome.ALLOW
    assert before.outcome == after.outcome
    assert before.reason == after.reason


def test_v01_policy_outcome_is_unaffected_and_distinct_from_the_new_type() -> None:
    """`basis_core.policy.engine.PolicyOutcome` (v0.1.0, a single-rule
    evaluation outcome) and this module's `OperationAwarePolicyOutcome`
    (an aggregated, bundle-level authorization outcome) are deliberately
    two distinct types — see the module docstring's naming-collision note.
    """
    from basis_core.policy.engine import PolicyOutcome as V01PolicyOutcome

    assert OperationAwarePolicyOutcome is not V01PolicyOutcome
    assert {member.value for member in V01PolicyOutcome} == {"allow", "deny", "not_applicable"}
    assert {member.value for member in OperationAwarePolicyOutcome} == {
        "allow",
        "deny",
        "not_applicable",
    }


def test_no_new_symbols_are_exported_from_basis_core_policy_package() -> None:
    """This PR does not stabilize a public API — `aggregation.py`'s
    symbols must not be re-exported from `basis_core.policy`."""
    import basis_core.policy as policy_package

    assert not hasattr(policy_package, "aggregate_policy_outcome")
    assert not hasattr(policy_package, "OperationAwarePolicyOutcome")
    assert not hasattr(policy_package, "OperationAwareFailureReason")
    assert not hasattr(policy_package, "PolicyAggregationResult")


def test_decisions_package_graduated_the_failure_reason_by_pr35() -> None:
    """Required test 9 (extended for PR 27A) asserted `OperationAwareFailureReason`
    stayed internal until stabilized. PR 35 (Milestone 11) is that
    stabilization: `basis_core.decisions.__all__` now includes it, per
    `docs/public-api.md`'s "Operation-aware public API (v0.2.0)" section
    and the same "add internally now, stabilize later" convention already
    applied to `ReasonCode` (see `tests/operation_aware/
    test_vocabulary_boundaries.py::TestPublicApiSurfaceGraduatedByPR35`)."""
    import basis_core.decisions as decisions_package
    from basis_core.decisions import operation_aware as concrete

    assert "OperationAwareFailureReason" in decisions_package.__all__
    assert decisions_package.OperationAwareFailureReason is concrete.OperationAwareFailureReason

    init_path = (
        Path(__file__).parent.parent.parent / "src" / "basis_core" / "decisions" / "__init__.py"
    )
    text = init_path.read_text(encoding="utf-8")
    assert "OperationAwareFailureReason" in text
