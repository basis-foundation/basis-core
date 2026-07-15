"""
basis_core.evaluation.operation_aware.trace_assembly — pure, deterministic
`TraceRuleEvidence`/`EvaluationTrace` assembly.

This is the first module added under `src/basis_core/evaluation/` (see
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`, Milestone 8,
PR 26 — "Trace assembly function"). Per `basis-architecture` ADR-0006, this
is evaluation-owned *orchestration*, not policy-owned *semantics*: it
translates already-evaluated policy facts (Milestone 6's structural-match
integration and Milestone 7's condition-evaluation results, both already
merged as `policy.operation_aware.condition_eval.RuleConditionEvaluation`)
into the audit-owned trace contracts (`TraceRuleEvidence`, `EvaluationTrace`
— PR 24/PR 25, unmodified) through explicit vocabulary mappings.

What this module does
──────────────────────
  - `assemble_rule_evidence(rule, evaluation)` maps one already-typed
    `OperationAwarePolicyRule` and its already-produced
    `RuleConditionEvaluation` into one `TraceRuleEvidence`, preserving the
    evaluator's own ordered `condition_results` (when any conditions were
    actually evaluated) and the rule's own authored `reason_code`/
    `explanation`.
  - `assemble_evaluation_trace(rule_evidence, ...)` composes an already-
    assembled, already-ordered sequence of `TraceRuleEvidence` plus
    caller-supplied, already-determined trace-level state
    (`evaluation_status`, `outcome`, `bundle_applicability`,
    `failure_reason`, identifiers, bundle metadata) into one `EvaluationTrace`.

What this module does not do
──────────────────────────────
Neither function evaluates a selector, evaluates a condition, determines
bundle applicability, selects candidate rules, aggregates rule effects,
applies deny precedence or default deny, determines `NOT_APPLICABLE`, or
chooses a final authorization outcome or its reason code — all of that
remains `policy/`-owned (see `docs/import-boundaries.md`,
`docs/kernel-constitution.md` Invariant 1). `evaluation_status`, `outcome`,
`bundle_applicability`, and `failure_reason` are received as inputs to
`assemble_evaluation_trace`, never derived from `rule_evidence`. This module
generates no identifier, reads no clock, uses no randomness, performs no
I/O, and mutates no input it is given — repeated calls with equal inputs
produce equal outputs.

Rule identity agreement
────────────────────────
`assemble_rule_evidence` requires `rule.rule_id == evaluation.rule_id`. A
caller that pairs a rule with a different rule's evaluator result is a
caller bug, not an authorization outcome; this module refuses to silently
prefer one identifier, overwrite either, or construct evidence under an
identifier neither input actually confirms. See `RuleIdentityMismatchError`.

Condition evidence — no synthetic states
──────────────────────────────────────────
`RuleConditionEvaluation.condition_results` (from
`policy.operation_aware.condition_eval`, PR 23, merged and unconditional at
this point in the roadmap) is already empty in exactly the two cases where
`TraceRuleEvidence.condition_results` must be absent — a structural selector
mismatch (conditions never reached) and a rule authored with no
`conditions` at all — and already holds the complete, ordered per-condition
result whenever conditions were actually evaluated (whether every condition
matched, some did not, or one raised an evaluation error). This module reads
that distinction directly off `evaluation.condition_results`; it never
infers "conditions pending" from rule shape on its own and never invents a
condition-evidence entry (no `unknown`/`not_evaluated`/synthetic `skipped`
value) for a condition that was not actually evaluated.

Vocabulary mappings (exhaustive, both directions bounded/closed)
───────────────────────────────────────────────────────────────
  `policy.operation_aware.rule.RuleEffect`
    → `audit.operation_aware.trace_rule_evidence.TraceRuleEffect`
      ALLOW → ALLOW, DENY → DENY.
  `policy.operation_aware.condition_eval.RuleConditionResult`
    → `audit.operation_aware.trace_rule_evidence.RuleResult`
      MATCHED → MATCHED, NOT_MATCHED → NOT_MATCHED, ERROR → ERROR.
      `RuleResult.SKIPPED` is never produced by this module:
      `RuleConditionEvaluation` has no vocabulary member meaning "this rule
      was never evaluated at all," so inventing `SKIPPED` from rule
      position or any other inference would not be an honest mapping of an
      evaluator fact — see this module's final PR report for the explicit
      note on why `SKIPPED` is unreachable here, by construction.
  `policy.operation_aware.operators.ConditionResult`
    → `audit.operation_aware.trace_rule_evidence.TraceConditionResult`
      MATCH → MATCHED, NO_MATCH → NOT_MATCHED, ERROR → ERROR.

Boundedness
────────────
Neither function copies a raw request, a full policy bundle, a full rule
(`match`/`conditions` authored content), a condition's `field_path`/
`operator`/`expected_value`, an actual compared value, an identity claim, a
token, or any other unbounded/raw evidence into the assembled trace. Bundle
metadata is limited to the two bounded scalar fields `EvaluationTrace`
already publishes (`bundle_id`, `bundle_version`); this module never
accepts or copies a full `PolicyBundle`.

Import boundary
────────────────
This module imports only from `basis_core.domain`, `basis_core.policy`,
and `basis_core.audit` (plus the standard library) — never from
`basis_core.adapters` or `basis_core.enforcement`. See
`docs/import-boundaries.md`; the recursive guard for this package's import
boundary lives in `tests/test_import_boundaries.py`.

Public API status: internal to the operation-aware package, exactly like
every other operation-aware module at this stage of the roadmap. Not
re-exported from `basis_core.evaluation`, `basis_core`, or any other
package `__init__.py`.
"""

from __future__ import annotations

from collections.abc import Sequence

from basis_core.audit.operation_aware.evaluation_trace import (
    EvaluationStatus,
    EvaluationTrace,
    TraceBundleApplicability,
    TraceFailureReason,
    TraceOutcome,
)
from basis_core.audit.operation_aware.trace_rule_evidence import (
    RuleResult,
    TraceConditionEvidence,
    TraceConditionResult,
    TraceRuleEffect,
    TraceRuleEvidence,
)
from basis_core.domain.operation_aware_vocabulary import ReasonCode
from basis_core.policy.operation_aware.condition_eval import (
    RuleConditionEvaluation,
    RuleConditionResult,
)
from basis_core.policy.operation_aware.operators import ConditionResult
from basis_core.policy.operation_aware.rule import OperationAwarePolicyRule, RuleEffect

__all__ = [
    "RuleIdentityMismatchError",
    "assemble_evaluation_trace",
    "assemble_rule_evidence",
]


class RuleIdentityMismatchError(ValueError):
    """
    Raised by `assemble_rule_evidence` when the authored
    `OperationAwarePolicyRule.rule_id` and the paired
    `RuleConditionEvaluation.rule_id` do not identify the same rule.

    This is a caller-input-consistency error, not an authorization outcome:
    it signals that the two arguments describe different rules, which this
    module refuses to resolve by silently preferring one identifier,
    overwriting either, or otherwise constructing evidence that does not
    honestly reflect both inputs. A single exception type is used
    deliberately — this failure has exactly one cause, so no exception
    hierarchy is warranted (contrast with `policy.operation_aware.
    validation.PolicyBundleValidationError`'s structural-vs-semantic
    hierarchy, which exists because that module has more than one kind of
    failure to distinguish).
    """


# ══════════════════════════════════════════════════════════════════════════
# Explicit, exhaustive vocabulary mappings
# ══════════════════════════════════════════════════════════════════════════

_RULE_EFFECT_TO_TRACE_RULE_EFFECT: dict[RuleEffect, TraceRuleEffect] = {
    RuleEffect.ALLOW: TraceRuleEffect.ALLOW,
    RuleEffect.DENY: TraceRuleEffect.DENY,
}

_RULE_CONDITION_RESULT_TO_RULE_RESULT: dict[RuleConditionResult, RuleResult] = {
    RuleConditionResult.MATCHED: RuleResult.MATCHED,
    RuleConditionResult.NOT_MATCHED: RuleResult.NOT_MATCHED,
    RuleConditionResult.ERROR: RuleResult.ERROR,
}

_CONDITION_RESULT_TO_TRACE_CONDITION_RESULT: dict[ConditionResult, TraceConditionResult] = {
    ConditionResult.MATCH: TraceConditionResult.MATCHED,
    ConditionResult.NO_MATCH: TraceConditionResult.NOT_MATCHED,
    ConditionResult.ERROR: TraceConditionResult.ERROR,
}


# ══════════════════════════════════════════════════════════════════════════
# Rule-evidence assembly
# ══════════════════════════════════════════════════════════════════════════


def assemble_rule_evidence(
    rule: OperationAwarePolicyRule,
    evaluation: RuleConditionEvaluation,
) -> TraceRuleEvidence:
    """
    Assemble one bounded `TraceRuleEvidence` from one already-typed,
    already-validated `OperationAwarePolicyRule` and the
    `RuleConditionEvaluation` already produced for it (by
    `policy.operation_aware.condition_eval.evaluate_rule_conditions`, or an
    equivalent already-evaluated result) against the same request.

    This function evaluates nothing. It maps already-determined facts
    through the explicit vocabulary tables above, preserves
    `evaluation.condition_results`' order exactly, and carries the rule's
    own authored `reason_code`/`explanation` forward unchanged.

    Rule identity agreement:
        `rule.rule_id` and `evaluation.rule_id` must be equal. If they are
        not, `RuleIdentityMismatchError` is raised — the two arguments do
        not honestly describe the same rule, and no dishonest evidence is
        constructed by preferring one identifier over the other.

    Condition evidence:
        `evaluation.condition_results` is empty exactly when this rule's
        conditions were never evaluated (a structural selector mismatch,
        or a rule authored with no `conditions` at all) — in both cases
        the assembled `TraceRuleEvidence.condition_results` is `None`
        (absent), never a synthetic or empty-but-present value. When
        `evaluation.condition_results` is non-empty, every entry is
        mapped, in order, into a `TraceConditionEvidence`; no entry is
        omitted and none is invented.

    Purity: reads `rule` and `evaluation` only; mutates neither. Performs
    no I/O, uses no clock or randomness, and generates no identifier —
    `rule_id`/`condition_id` values are taken from the inputs unchanged.

    Args:
        rule: the authored `OperationAwarePolicyRule` this evidence
            describes.
        evaluation: the `RuleConditionEvaluation` already produced for
            `rule` against one request.

    Returns:
        A validated `TraceRuleEvidence` (constructed through normal
        Pydantic validation — never `model_construct`).

    Raises:
        RuleIdentityMismatchError: if `rule.rule_id != evaluation.rule_id`.
    """
    if rule.rule_id != evaluation.rule_id:
        raise RuleIdentityMismatchError(
            "assemble_rule_evidence received a rule and an evaluator result for "
            f"different rules: rule.rule_id={rule.rule_id!r}, "
            f"evaluation.rule_id={evaluation.rule_id!r}. Refusing to construct trace "
            "evidence under either identifier alone."
        )

    condition_results: list[TraceConditionEvidence] | None
    if evaluation.condition_results:
        condition_results = [
            TraceConditionEvidence(
                condition_id=condition_evaluation.condition_id,
                result=_CONDITION_RESULT_TO_TRACE_CONDITION_RESULT[condition_evaluation.result],
            )
            for condition_evaluation in evaluation.condition_results
        ]
    else:
        condition_results = None

    return TraceRuleEvidence(
        rule_id=rule.rule_id,
        effect=_RULE_EFFECT_TO_TRACE_RULE_EFFECT[rule.effect],
        rule_result=_RULE_CONDITION_RESULT_TO_RULE_RESULT[evaluation.result],
        condition_results=condition_results,
        reason_code=rule.reason_code,
        explanation=rule.explanation,
    )


# ══════════════════════════════════════════════════════════════════════════
# Evaluation-trace assembly
# ══════════════════════════════════════════════════════════════════════════


def assemble_evaluation_trace(
    rule_evidence: Sequence[TraceRuleEvidence],
    *,
    trace_id: str,
    request_id: str,
    evaluation_status: EvaluationStatus,
    outcome: TraceOutcome | None,
    bundle_applicability: TraceBundleApplicability | None,
    correlation_id: str | None = None,
    bundle_id: str | None = None,
    bundle_version: str | None = None,
    failure_reason: TraceFailureReason | None = None,
    reason_code: ReasonCode | None = None,
    explanation: str | None = None,
) -> EvaluationTrace:
    """
    Compose one `EvaluationTrace` from an already-assembled, already-ordered
    sequence of `TraceRuleEvidence` and caller-supplied, already-determined
    trace-level state.

    This function determines nothing about authorization. `evaluation_status`,
    `outcome`, `bundle_applicability`, and `failure_reason` are received
    exactly as the caller supplies them — this function does not inspect
    `rule_evidence` to infer, override, or cross-check any of them beyond
    whatever `EvaluationTrace`'s own construction-time validators already
    enforce (e.g. a `rule_result: error` entry requiring
    `evaluation_status: failed`). Identifiers (`trace_id`, `request_id`,
    `correlation_id`) are preserved exactly as supplied; none is generated.
    Bundle metadata is limited to the two bounded scalar fields
    `EvaluationTrace` already publishes (`bundle_id`, `bundle_version`) —
    never a full `PolicyBundle`.

    Ordering: `rule_evidence` is preserved in exactly the sequence supplied
    — never sorted, deduplicated, or reordered by `rule_id`, `effect`, or
    `rule_result`. Array position here is trace-evidence order, not
    authorization precedence.

    Purity: reads `rule_evidence` only; does not mutate the sequence or any
    element within it (`list(rule_evidence)` always builds a new list).
    Performs no I/O, uses no clock or randomness, and generates no
    identifier.

    Args:
        rule_evidence: already-assembled `TraceRuleEvidence` instances (for
            example, from repeated calls to `assemble_rule_evidence`), in
            the exact order they should appear in the trace. May be empty
            (required when `bundle_applicability` is `not_applicable`, and
            for a failed evaluation that never reached rule evaluation).
        trace_id: caller-supplied, preserved exactly; never generated here.
        request_id: caller-supplied, preserved exactly; never generated
            here.
        evaluation_status: already-determined `EvaluationStatus`.
        outcome: already-determined `TraceOutcome`, or `None` (required
            when `evaluation_status` is `failed`).
        bundle_applicability: already-determined `TraceBundleApplicability`,
            or `None` (required when `evaluation_status` is `failed`).
        correlation_id: caller-supplied, preserved exactly; optional.
        bundle_id: bounded bundle identifier scalar; optional.
        bundle_version: bounded bundle version scalar; optional.
        failure_reason: already-determined `TraceFailureReason`, required
            (non-`None`) exactly when `evaluation_status` is `failed`.
        reason_code: an already-determined, bounded `ReasonCode`; optional.
        explanation: an already-determined, bounded static explanation
            string; optional.

    Returns:
        A validated `EvaluationTrace` (constructed through normal Pydantic
        validation — never `model_construct`); every one of that model's
        own cross-field invariants is enforced at construction time.
    """
    return EvaluationTrace(
        trace_id=trace_id,
        request_id=request_id,
        correlation_id=correlation_id,
        evaluation_status=evaluation_status,
        outcome=outcome,
        bundle_applicability=bundle_applicability,
        bundle_id=bundle_id,
        bundle_version=bundle_version,
        failure_reason=failure_reason,
        rule_evidence=list(rule_evidence),
        reason_code=reason_code,
        explanation=explanation,
    )
