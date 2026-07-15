"""
basis_core.policy.operation_aware.condition_eval — rule-level condition
evaluation integration.

Integrates `selector.py`'s structural match classification with
`operators.py`'s standalone per-condition evaluation into one rule-level
result:

  RuleConditionResult        Closed, three-value result: `matched` /
                              `not_matched` / `error`. Not an authorization
                              outcome, and not the (distinct) trace-evidence
                              `rule_result` vocabulary.
  RuleConditionEvaluation    Immutable `(rule_id, result, condition_results)`
                              result. `condition_results` is an ordered,
                              immutable tuple of `ConditionEvaluation`, in
                              authored order.
  evaluate_rule_conditions() The single public entry point:
                              `(OperationAwarePolicyRule,
                              OperationAwareDecisionRequest) ->
                              RuleConditionEvaluation`.

Behavior
────────
A structural selector mismatch is reported `not_matched` without evaluating
any condition. A structural match with no conditions is reported `matched`
immediately. Otherwise, every condition in `rule.conditions` is evaluated
exactly once, in authored order, by calling `operators.py`'s
`evaluate_condition` — this module performs no operator dispatch, field-path
resolution, or comparison of its own. No condition evaluation is skipped and
none is short-circuited: the full, ordered per-condition result sequence is
always retained, regardless of the aggregate outcome. Aggregation: any
condition `error` makes the rule `error` (this dominates `no_match`);
otherwise, if every condition `match`, the rule is `matched`; otherwise the
rule is `not_matched`.

This module does not apply `rule.effect`, and does not implement deny
precedence, default deny, or any final authorization outcome. It does not
construct trace or audit evidence, and introduces no `basis_core.audit`
dependency.

`RuleConditionEvaluation` is immutable (frozen dataclass, tuple-typed
`condition_results`) and bounded — it carries `rule.rule_id` as a stable
identifier only, never a copy of the rule or the request.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from basis_core.decisions.operation_aware import OperationAwareDecisionRequest
from basis_core.policy.operation_aware.operators import (
    ConditionEvaluation,
    ConditionResult,
    evaluate_condition,
)
from basis_core.policy.operation_aware.rule import OperationAwarePolicyRule
from basis_core.policy.operation_aware.selector import (
    SelectorMatchResult,
    evaluate_rule_selectors,
)

__all__ = [
    "RuleConditionEvaluation",
    "RuleConditionResult",
    "evaluate_rule_conditions",
]


# ══════════════════════════════════════════════════════════════════════════
# Result vocabulary
# ══════════════════════════════════════════════════════════════════════════


class RuleConditionResult(str, Enum):
    """
    Closed, three-value rule-level condition-integration result:
    `matched` / `not_matched` / `error`. Not an authorization outcome
    (`allow`/`deny`/`not_applicable`), and not the separate, four-value
    trace-evidence `rule_result` vocabulary.
    """

    MATCHED = "matched"
    NOT_MATCHED = "not_matched"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class RuleConditionEvaluation:
    """
    Immutable result of integrating one rule's structural selector outcome
    with its declared conditions' evaluation, against one request.

      rule_id            The evaluated rule's `rule_id` — a stable
                         identifier only, never a copy of the rule or the
                         request.
      result              The aggregate `RuleConditionResult`.
      condition_results   Ordered, immutable tuple of `ConditionEvaluation`,
                         one per authored condition, in authored order.
                         Empty when conditions were not evaluated (a
                         structural selector mismatch) or there were none
                         to evaluate.

    Carries no raw request or rule content beyond `rule_id`, no exception
    detail, and no authorization-effect, trace, or audit field.
    """

    rule_id: str
    result: RuleConditionResult
    condition_results: tuple[ConditionEvaluation, ...]


# ══════════════════════════════════════════════════════════════════════════
# Public entry point
# ══════════════════════════════════════════════════════════════════════════


def evaluate_rule_conditions(
    rule: OperationAwarePolicyRule,
    request: OperationAwareDecisionRequest,
) -> RuleConditionEvaluation:
    """
    Integrate `rule`'s structural selector outcome with its declared
    conditions' evaluation against `request`, producing one aggregate,
    rule-level `RuleConditionEvaluation`.

    Calls `evaluate_rule_selectors(rule, request)` once, and — only when its
    result reports `conditions_pending=True` — calls
    `evaluate_condition(condition, request)` once per entry in
    `rule.conditions`, in authored order, evaluating every condition in full
    (no short-circuit after a `no_match` or an `error`).

    Aggregation:

        selector result                              conditions evaluated?   rule result
        ────────────────────────────────────────     ──────────────────────  ───────────
        NOT_MATCHED, conditions_pending=False         no                     not_matched
        MATCHED                                       no (none declared)     matched
        conditions_pending=True, every condition MATCH  yes (all)            matched
        conditions_pending=True, any NO_MATCH, no ERROR yes (all)            not_matched
        conditions_pending=True, any ERROR              yes (all)            error

    Args:
        rule: an already-constructed, already-validated
            `OperationAwarePolicyRule`.
        request: an already-constructed, already-validated
            `OperationAwareDecisionRequest`.

    Returns:
        A `RuleConditionEvaluation` carrying `rule.rule_id`, the aggregate
        `RuleConditionResult`, and the ordered `condition_results` tuple
        (possibly empty).
    """
    selector_evaluation = evaluate_rule_selectors(rule, request)

    if selector_evaluation.result is SelectorMatchResult.MATCHED:
        # Structural selectors satisfied and `rule.conditions` is empty —
        # nothing remains to evaluate.
        return RuleConditionEvaluation(
            rule_id=rule.rule_id,
            result=RuleConditionResult.MATCHED,
            condition_results=(),
        )

    if not selector_evaluation.conditions_pending:
        # A structural `match` mismatch already made a match impossible.
        # Conditions are deliberately never evaluated for a structurally
        # nonmatching rule.
        return RuleConditionEvaluation(
            rule_id=rule.rule_id,
            result=RuleConditionResult.NOT_MATCHED,
            condition_results=(),
        )

    # Structural selectors are satisfied (or `rule.match` is absent
    # entirely) and `rule.conditions` remains to be evaluated — guaranteed
    # non-empty here by `OperationAwarePolicyRule`'s own construction-time
    # invariant. Evaluate every condition, in authored order, in full —
    # never short-circuiting after a `no_match` or an `error`.
    condition_results = tuple(
        evaluate_condition(condition, request) for condition in rule.conditions or ()
    )

    if any(evaluation.result is ConditionResult.ERROR for evaluation in condition_results):
        aggregate_result = RuleConditionResult.ERROR
    elif all(evaluation.result is ConditionResult.MATCH for evaluation in condition_results):
        aggregate_result = RuleConditionResult.MATCHED
    else:
        aggregate_result = RuleConditionResult.NOT_MATCHED

    return RuleConditionEvaluation(
        rule_id=rule.rule_id,
        result=aggregate_result,
        condition_results=condition_results,
    )
