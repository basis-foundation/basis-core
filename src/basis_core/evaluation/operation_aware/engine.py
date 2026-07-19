"""
basis_core.evaluation.operation_aware.engine — the
`OperationAwareEvaluationEngine` deterministic orchestration engine.

This is the second module added under `src/basis_core/evaluation/
operation_aware/` (see
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`, Milestone 9,
PR 27B — "Evaluation-owned orchestration engine"), after PR 26's
`trace_assembly.py`. Per `basis-architecture` ADR-0006 and its companion
document (`docs/architecture/operation-aware-evaluation-orchestration.md`),
this module is the pure evaluation *orchestration* layer: it sequences and
composes the already-implemented `policy/`-owned semantic operations and
`audit/`-owned trace contracts into one deterministic
`basis_core.audit.operation_aware.evaluation_trace.EvaluationTrace`. It
reimplements none of their semantics.

  OperationAwareEvaluationEngine   The single class this module exports.
                                    One public method, `evaluate()`. Stateless
                                    — see "Statelessness" below.

Sequence orchestrated (ADR-0002 Section 3; this module's own required
sequence)
────────────────────────────────────────────────────────────────────────
    typed request + typed policy bundle + caller-supplied trace ID
            v
    policy bundle semantic validation           (policy.operation_aware.validation)
            v
    bundle applicability                        (policy.operation_aware.applicability)
            v
    deterministic candidate selection            (policy.operation_aware.selector)
            v
    selector and condition evaluation            (policy.operation_aware.condition_eval)
            v
    policy-owned aggregation                     (policy.operation_aware.aggregation)
            v
    bounded rule-evidence assembly                (evaluation.operation_aware.trace_assembly)
            v
    evaluation-trace assembly                     (evaluation.operation_aware.trace_assembly)
            v
    EvaluationTrace

Every arrow above is a call into an already-implemented, already-tested
function or class from a sibling module. This module adds no new
authorization semantics: no applicability rule, no selector-matching rule,
no condition-operator behavior, no deny-precedence/allow/default-deny/
NOT_APPLICABLE rule, and no trace-model invariant. Where this docstring
describes "the engine decides," it means the engine decides *which
already-implemented operation to call next and how to carry its typed
result forward* — never what that operation's own answer means.

Engine naming
──────────────
Named `OperationAwareEvaluationEngine`, not `OperationAwarePolicyEngine`.
`OperationAwarePolicyEngine` is not defined anywhere in this module, this
package, or re-exported by it, and no compatibility alias is provided — see
`tests/operation_aware/test_evaluation_engine.py`'s naming tests. The name
reflects the architectural distinction this repository's roadmap plan and
ADR-0006 both draw: `policy/` owns executable authorization semantics;
`evaluation/` orchestrates those semantics. This class is the `evaluation/`
half of that distinction, not a second policy engine.

Statelessness
──────────────
`OperationAwareEvaluationEngine` holds no constructor arguments and no
instance attributes. It is a plain, stateless callable wrapper around
`evaluate()` — a class only so a caller has a stable, named, importable
entry point to construct once and reuse, exactly as `basis_core.policy.
engine.PolicyEngine` and `basis_core.enforcement.enforcement.EnforcementPoint`
already are for the v0.1.0 kernel. No configurable strategy object, no
constructor-supplied policy source, no cache, and no mutable field of any
kind is added. Repeated calls to `evaluate()` on the same instance, or on
different instances, with equal inputs, produce equal `EvaluationTrace`
values — see "Determinism" below.

Return type
────────────
`evaluate()` returns `EvaluationTrace` directly — not a new, engine-specific
result wrapper. `EvaluationTrace` (PR 25) already represents both a
completed and a failed evaluation in full; `aggregate_policy_outcome` (PR
27A) already supplies the authoritative status/outcome/failure-reason facts
this trace reports. `OperationAwareDecisionResponse` (response assembly) is
explicitly later, separately-scoped roadmap work (PR 29 onward) — introducing
a second, engine-specific result model now would risk duplicating that
future contract before it exists. Nothing in the merged roadmap or the
architecture documents inspected for this PR requires an intermediate
engine-result wrapper; none is added.

Entry point
────────────
    engine = OperationAwareEvaluationEngine()
    trace = engine.evaluate(request=..., bundle=..., trace_id=...)

`request` must already be a typed `OperationAwareDecisionRequest`. `bundle`
must already be a typed `PolicyBundle`. `trace_id` is supplied by the
caller; the engine never generates one. Keyword-only arguments are used
throughout so the three identifiers this call handles (a request, a bundle,
and a trace ID) can never be confused positionally.

What this engine does not do (mirrors ADR-0006's non-goals for this layer)
────────────────────────────────────────────────────────────────────────
It does not determine bundle applicability, match selectors, evaluate
conditions, aggregate rule effects, decide deny precedence, decide
allow/default-deny, decide `NOT_APPLICABLE`, validate policy semantics, or
enforce any trace-model invariant — all of that is owned, and already
implemented, by the sibling modules this engine calls. It does not
implement `OperationAwareDecisionResponse`, `AuditEvidence`,
`OperationAwareEnforcementPoint`, or any gateway/enforcement behavior. It
does not read a clock, generate a UUID, use randomness, perform I/O, load
policy from a path, retrieve external context, or accept a raw dictionary
in place of a typed request/bundle. It does not mutate the request, the
bundle, any rule, or its own prior result.

Policy-validation failure mapping — staged structural/semantic boundary
────────────────────────────────────────────────────────────────────────
`validate_policy_bundle` (PR 15) raises one of two `PolicyBundleValidationError`
subclasses: `StructuralPolicyValidationError` (malformed shape — a raw
mapping `PolicyBundle.model_validate` itself rejects) or
`SemanticPolicyValidationError` (a structurally well-formed bundle that
violates a cross-object invariant — today, exactly two concrete cases:
`DuplicateRuleIdError` and `DuplicateConditionIdError`).

This engine's `bundle` parameter is already a typed `PolicyBundle` (never a
raw mapping — see "Entry point" above), so `validate_policy_bundle` always
takes its "already a `PolicyBundle`" branch and never re-runs
`PolicyBundle.model_validate`. `StructuralPolicyValidationError` is
therefore unreachable through this engine's typed entry point, exactly as
request-shape structural failure is unreachable through it (see the
"Request structural failures" non-goal above) — both are
upstream-of-this-engine concerns by construction. This module does not add
an unreachable `except StructuralPolicyValidationError` branch merely to
exercise `invalid_policy_bundle`; a raw, unparsed bundle's structural
failure is a concern for whatever future parsing/enforcement boundary
accepts raw mappings, not for this typed engine.

The reachable case is `SemanticPolicyValidationError` (its two current
subclasses, `DuplicateRuleIdError` and `DuplicateConditionIdError`). This
module catches `SemanticPolicyValidationError` specifically — not the
`PolicyBundleValidationError` root — and maps it to
`OperationAwareFailureReason.POLICY_VALIDATION_FAILURE`, mirroring the
existing exception hierarchy's own structural-versus-semantic distinction
one-for-one:

    StructuralPolicyValidationError → invalid_policy_bundle
        (unreachable here — raw-mapping/parsing boundary's concern)
    SemanticPolicyValidationError   → policy_validation_failure
        (reachable here — this engine's typed-bundle boundary)

**Known upstream conflict, not resolved here.** The vendored canonical-vector
fixture `tests/fixtures/basis-schemas/v0.2.0/compatibility/invalid-policy-bundle/
expected-evaluation-trace.yaml` — a duplicate-`rule_id` scenario — currently
asserts `failure_reason: invalid_policy_bundle` for exactly the case this
module classifies as `policy_validation_failure` under the typed
structural/semantic boundary above. This module does not silently resolve
that conflict by picking whichever value the fixture happens to contain. It
follows the typed structural-versus-semantic validation boundary this
repository's own exception hierarchy already establishes, and defers
reconciling the vendored fixture's classification to upstream
`basis-schemas` work — see the PR 27B roadmap status note in
`docs/implementation/basis-core-v0.2-operation-aware-plan.md` for the
explicit pending-reconciliation statement. This module does not modify the
vendored fixture, and this PR does not claim full canonical-vector
conformance (that remains PR 28's, and ultimately Milestone 12's, scope).

Because only `DuplicateRuleIdError`/`DuplicateConditionIdError` are
reachable today, and both map to `POLICY_VALIDATION_FAILURE`, this engine
never constructs `OperationAwareFailureReason.INVALID_POLICY_BUNDLE` —
mirroring the same documented, honest scope limitation
`aggregate_policy_outcome` (PR 27A) already applies to the five failure
members it does not construct.

Condition-evaluation-error propagation
────────────────────────────────────────
A rule whose conditions cannot be evaluated produces
`RuleConditionResult.ERROR` from `evaluate_rule_conditions`; this engine
carries that fact into an `EvaluatedRule` unchanged, `aggregate_policy_outcome`
(not this engine) determines that any `ERROR` dominates deny precedence and
allow determination and produces `PolicyAggregationStatus.FAILED` with
`failure_reason=CONDITION_EVALUATION_ERROR`, and this engine maps that
failure category into the trace's `TraceFailureReason.CONDITION_EVALUATION_ERROR`
via the same explicit mapping table used for every other failure member.
The errored rule's own evidence is still assembled via `assemble_rule_evidence`
and included in the trace's `rule_evidence` — never discarded — exactly
like every other evaluated rule in the same evaluation.

Unexpected-exception handling
───────────────────────────────
This module adds no `except Exception` clause anywhere. `SemanticPolicyValidationError`
is the one exception type this engine catches, deliberately and narrowly,
because it is a known, typed, documented evaluator-failure signal this
engine is specifically responsible for mapping into a failed trace — see
"Policy-validation failure mapping" above for why `StructuralPolicyValidationError`
is deliberately *not* caught (it is unreachable through this engine's typed
entry point, and this module does not add a branch for it merely to
exercise `invalid_policy_bundle`). Any other exception — a defect in this
engine's own wiring, or an unexpected failure inside a sibling module —
propagates uncaught. Converting arbitrary exceptions into
`internal_evaluation_error` is fail-closed *enforcement* behavior; per
`docs/kernel-constitution.md` and this PR's brief, that remains the future
enforcement boundary's responsibility, not this pure orchestration
engine's.

Determinism
────────────
`evaluate()` reads its three arguments only; it never mutates the request,
the bundle, any nested rule/condition, or itself. It calls no clock, no
UUID generator, no random-value source, and performs no I/O of any kind —
every value in the returned `EvaluationTrace` is either supplied by the
caller (`trace_id`) or derived from the request/bundle (`request_id`,
`correlation_id`, `bundle_id`, `bundle_version`) or from a pure function
call chain rooted in `request`/`bundle`. Identical `request`/`bundle`/
`trace_id` arguments always produce an equal `EvaluationTrace`; repeated
calls do not accumulate any state, because none is held.

Import boundary
────────────────
This module imports from `basis_core.audit.operation_aware`,
`basis_core.decisions.operation_aware`, `basis_core.evaluation.operation_aware`
(its own sibling, `trace_assembly`), and `basis_core.policy.operation_aware`
— all legal per `docs/import-boundaries.md` (`evaluation/` may import
`domain/`, `decisions/`, `policy/`, `audit/`). It does not import
`basis_core.adapters` or `basis_core.enforcement` — enforced by the
existing recursive guard, `tests/test_import_boundaries.py::
test_evaluation_operation_aware_does_not_import_from_adapters_or_enforcement`.

Public API status: internal to the operation-aware package, exactly like
every other operation-aware module added so far. Not re-exported from
`basis_core.evaluation`, `basis_core`, or any other package `__init__.py`.
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
from basis_core.audit.operation_aware.trace_rule_evidence import TraceRuleEvidence
from basis_core.decisions.operation_aware import (
    OperationAwareDecisionRequest,
    OperationAwareFailureReason,
)
from basis_core.evaluation.operation_aware.trace_assembly import (
    assemble_evaluation_trace,
    assemble_rule_evidence,
)
from basis_core.policy.operation_aware.aggregation import (
    EvaluatedRule,
    OperationAwarePolicyOutcome,
    PolicyAggregationResult,
    PolicyAggregationStatus,
    aggregate_policy_outcome,
)
from basis_core.policy.operation_aware.applicability import (
    ApplicabilityResult,
    determine_applicability,
)
from basis_core.policy.operation_aware.bundle import PolicyBundle
from basis_core.policy.operation_aware.condition_eval import evaluate_rule_conditions
from basis_core.policy.operation_aware.selector import select_candidate_rules
from basis_core.policy.operation_aware.validation import (
    SemanticPolicyValidationError,
    validate_policy_bundle,
)

__all__ = ["OperationAwareEvaluationEngine"]


# ══════════════════════════════════════════════════════════════════════════
# Explicit, exhaustive vocabulary mappings (Stage 8)
# ══════════════════════════════════════════════════════════════════════════
#
# Each table is deliberately a plain `dict` keyed by every member of its
# source enum, never a `.value`-string coercion (`TraceEnum(policy_enum.value)`)
# and never a fallback/default branch. A membership-completeness test in
# `tests/operation_aware/test_evaluation_engine.py` walks each source enum
# and asserts every member has an explicit entry here — so an enum member
# added to any source vocabulary without a reviewed update to the matching
# table below fails that test loudly, rather than silently falling through
# to a guessed mapping at runtime.

_APPLICABILITY_TO_TRACE_BUNDLE_APPLICABILITY: dict[
    ApplicabilityResult, TraceBundleApplicability
] = {
    ApplicabilityResult.APPLICABLE: TraceBundleApplicability.APPLICABLE,
    ApplicabilityResult.NOT_APPLICABLE: TraceBundleApplicability.NOT_APPLICABLE,
}

_AGGREGATION_STATUS_TO_EVALUATION_STATUS: dict[PolicyAggregationStatus, EvaluationStatus] = {
    PolicyAggregationStatus.COMPLETED: EvaluationStatus.COMPLETED,
    PolicyAggregationStatus.FAILED: EvaluationStatus.FAILED,
}

_POLICY_OUTCOME_TO_TRACE_OUTCOME: dict[OperationAwarePolicyOutcome, TraceOutcome] = {
    OperationAwarePolicyOutcome.ALLOW: TraceOutcome.ALLOW,
    OperationAwarePolicyOutcome.DENY: TraceOutcome.DENY,
    OperationAwarePolicyOutcome.NOT_APPLICABLE: TraceOutcome.NOT_APPLICABLE,
}

_FAILURE_REASON_TO_TRACE_FAILURE_REASON: dict[OperationAwareFailureReason, TraceFailureReason] = {
    OperationAwareFailureReason.INVALID_REQUEST: TraceFailureReason.INVALID_REQUEST,
    OperationAwareFailureReason.UNSUPPORTED_SCHEMA_VERSION: (
        TraceFailureReason.UNSUPPORTED_SCHEMA_VERSION
    ),
    OperationAwareFailureReason.INVALID_POLICY_BUNDLE: TraceFailureReason.INVALID_POLICY_BUNDLE,
    OperationAwareFailureReason.POLICY_VALIDATION_FAILURE: (
        TraceFailureReason.POLICY_VALIDATION_FAILURE
    ),
    OperationAwareFailureReason.CONDITION_EVALUATION_ERROR: (
        TraceFailureReason.CONDITION_EVALUATION_ERROR
    ),
    OperationAwareFailureReason.INTERNAL_EVALUATION_ERROR: (
        TraceFailureReason.INTERNAL_EVALUATION_ERROR
    ),
}


# ══════════════════════════════════════════════════════════════════════════
# The engine
# ══════════════════════════════════════════════════════════════════════════


class OperationAwareEvaluationEngine:
    """
    Deterministic evaluation-orchestration engine for operation-aware
    authorization. See this module's docstring for the full architectural
    boundary, sequencing, mapping tables, and determinism guarantees.

    Stateless: holds no constructor arguments and no instance attributes.
    """

    def evaluate(
        self,
        *,
        request: OperationAwareDecisionRequest,
        bundle: PolicyBundle,
        trace_id: str,
    ) -> EvaluationTrace:
        """
        Evaluate `request` against `bundle`, returning a complete
        `EvaluationTrace` under `trace_id`.

        Args:
            request: an already-constructed, already-validated
                `OperationAwareDecisionRequest`.
            bundle: an already-constructed `PolicyBundle`. Its own semantic
                validity (`rule_id`/`condition_id` uniqueness) is checked by
                this call, before any applicability, selection, condition,
                or aggregation stage runs — see "Policy-validation failure
                mapping" in this module's docstring.
            trace_id: caller-supplied; never generated by this engine.

        Returns:
            A validated `EvaluationTrace` — completed (`allow`/`deny`/
            `not_applicable`) or failed (`policy_validation_failure` or
            `condition_evaluation_error`, the only two failure categories
            reachable through this engine's typed entry point today).
        """
        # ── Stage 1: policy bundle semantic validation ──────────────────
        # An invalid policy must never reach applicability, selection,
        # condition evaluation, or aggregation. Only `SemanticPolicyValidationError`
        # is caught here — not the `PolicyBundleValidationError` root —
        # because `StructuralPolicyValidationError` is unreachable through
        # this engine's typed `bundle: PolicyBundle` entry point (see this
        # module's docstring, "Policy-validation failure mapping"). Every
        # reachable failure here maps to `POLICY_VALIDATION_FAILURE`.
        try:
            validated_bundle = validate_policy_bundle(bundle)
        except SemanticPolicyValidationError:
            return assemble_evaluation_trace(
                (),
                trace_id=trace_id,
                request_id=request.request_id,
                correlation_id=request.correlation_id,
                evaluation_status=EvaluationStatus.FAILED,
                outcome=None,
                bundle_applicability=None,
                bundle_id=bundle.bundle_id,
                bundle_version=bundle.bundle_version,
                failure_reason=_FAILURE_REASON_TO_TRACE_FAILURE_REASON[
                    OperationAwareFailureReason.POLICY_VALIDATION_FAILURE
                ],
                reason_code=None,
                explanation=None,
            )

        # ── Stage 2: bundle applicability ───────────────────────────────
        applicability = determine_applicability(validated_bundle, request)

        if applicability is ApplicabilityResult.NOT_APPLICABLE:
            # Skip selector evaluation and condition evaluation entirely —
            # a non-applicable bundle has no candidate rules (Stage 3-4
            # never run). Policy aggregation is still invoked, with no
            # evaluated rules, so that a completed NOT_APPLICABLE result
            # (never DENY) comes from the same policy-owned aggregation
            # function every other path uses.
            aggregation_result = aggregate_policy_outcome(applicability, ())
            return self._assemble_trace(
                trace_id=trace_id,
                request=request,
                bundle=validated_bundle,
                applicability=applicability,
                rule_evidence=(),
                aggregation_result=aggregation_result,
            )

        # ── Stage 3: deterministic candidate and selector evaluation ────
        # `select_candidate_rules` returns every rule's `CandidateRuleEvaluation`
        # in its own established deterministic order (ascending `rule_id`).
        # This engine preserves that order end to end; it never re-sorts,
        # filters, or otherwise reinterprets it.
        candidates = select_candidate_rules(validated_bundle.rules, request)

        # ── Stage 4: rule-level condition evaluation ────────────────────
        # ── Stage 5: build policy aggregation facts ─────────────────────
        # One pass over `candidates`, in their established order:
        # `evaluate_rule_conditions` integrates the selector stage (which
        # this engine does not duplicate) with condition evaluation, and
        # its result is carried into the smallest fact `aggregate_policy_
        # outcome` needs — never the rule's `match`/`conditions`/`reason_
        # code`/`explanation`, and never raw request data.
        rule_condition_evaluations = [
            evaluate_rule_conditions(candidate.rule, request) for candidate in candidates
        ]
        evaluated_rules: list[EvaluatedRule] = [
            EvaluatedRule(
                rule_id=candidate.rule.rule_id,
                effect=candidate.rule.effect,
                result=rule_condition_evaluation.result,
            )
            for candidate, rule_condition_evaluation in zip(
                candidates, rule_condition_evaluations, strict=True
            )
        ]

        # ── Stage 6: policy-owned aggregation ────────────────────────────
        # Accepted as authoritative for completed/failed state, outcome,
        # failure reason, final reason code, deny precedence, allow
        # behavior, default deny, and NOT_APPLICABLE — this engine does not
        # re-scan `evaluated_rules` to re-derive any of that.
        aggregation_result = aggregate_policy_outcome(applicability, evaluated_rules)

        # ── Stage 7: assemble ordered rule evidence ─────────────────────
        # Every rule actually evaluated gets evidence, in the same
        # established order — pairing each rule with the exact
        # `RuleConditionEvaluation` computed for it above (never a
        # positional `zip()` assumption alone: `evaluate_rule_conditions`
        # already stamps its result with that same rule's own `rule_id`,
        # so `assemble_rule_evidence`'s own identity check is a genuine
        # confirmation, not a formality).
        rule_evidence: list[TraceRuleEvidence] = [
            assemble_rule_evidence(candidate.rule, rule_condition_evaluation)
            for candidate, rule_condition_evaluation in zip(
                candidates, rule_condition_evaluations, strict=True
            )
        ]

        # ── Stage 8-9: explicit type mapping + evaluation-trace assembly ─
        return self._assemble_trace(
            trace_id=trace_id,
            request=request,
            bundle=validated_bundle,
            applicability=applicability,
            rule_evidence=rule_evidence,
            aggregation_result=aggregation_result,
        )

    @staticmethod
    def _assemble_trace(
        *,
        trace_id: str,
        request: OperationAwareDecisionRequest,
        bundle: PolicyBundle,
        applicability: ApplicabilityResult,
        rule_evidence: Sequence[TraceRuleEvidence],
        aggregation_result: PolicyAggregationResult,
    ) -> EvaluationTrace:
        """
        Shared Stage 8 (explicit type mapping) + Stage 9 (trace assembly)
        composition for both the applicable and non-applicable paths.
        """
        outcome = (
            _POLICY_OUTCOME_TO_TRACE_OUTCOME[aggregation_result.outcome]
            if aggregation_result.outcome is not None
            else None
        )
        failure_reason = (
            _FAILURE_REASON_TO_TRACE_FAILURE_REASON[aggregation_result.failure_reason]
            if aggregation_result.failure_reason is not None
            else None
        )
        return assemble_evaluation_trace(
            rule_evidence,
            trace_id=trace_id,
            request_id=request.request_id,
            correlation_id=request.correlation_id,
            evaluation_status=_AGGREGATION_STATUS_TO_EVALUATION_STATUS[aggregation_result.status],
            outcome=outcome,
            bundle_applicability=_APPLICABILITY_TO_TRACE_BUNDLE_APPLICABILITY[applicability],
            bundle_id=bundle.bundle_id,
            bundle_version=bundle.bundle_version,
            failure_reason=failure_reason,
            reason_code=aggregation_result.reason_code,
            explanation=None,
        )
