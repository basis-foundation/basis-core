"""
basis_core.policy.operation_aware.aggregation — deterministic, policy-owned
effect aggregation and final authorization-outcome semantics.

This module is the sixth module added under `src/basis_core/policy/
operation_aware/` for `basis-core` v0.2.0 (see
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`, Milestone 9,
PR 27 — "Effect aggregation and final-outcome semantics (policy-owned)"),
after PR 12's `condition.py`, PR 13's `rule.py`, PR 14's `bundle.py`, PR 15's
`validation.py`, and PR 17's `applicability.py`. It answers the one question
none of those modules answers: given a bundle's applicability and an
ordered set of already-evaluated rule facts, what is the final policy
evaluation result?

  aggregate_policy_outcome()    The single public entry point. A pure
                                 function: `(ApplicabilityResult,
                                 Sequence[EvaluatedRule]) ->
                                 PolicyAggregationResult`.
  EvaluatedRule                 The smallest immutable, policy-owned fact
                                 this module needs about one already-
                                 evaluated rule: its stable identity, its
                                 authored effect, and its condition-
                                 evaluation result.
  PolicyAggregationResult       Immutable, deterministic aggregation
                                 result: evaluation status, authorization
                                 outcome (when completed), failure reason
                                 (when failed), and a fixed, generic final
                                 reason code (when completed).
  PolicyAggregationStatus       Closed, two-value vocabulary distinguishing
                                 a completed aggregation from one that
                                 could not be completed because a rule
                                 could not be evaluated (`failed`).
  OperationAwarePolicyOutcome   Closed, three-value authorization-outcome
                                 vocabulary (`allow` / `deny` /
                                 `not_applicable`), policy-owned and
                                 distinct from `basis_core.audit.
                                 operation_aware.evaluation_trace.
                                 TraceOutcome` — see "Import boundary and
                                 vocabulary ownership" below. Named
                                 `OperationAwarePolicyOutcome`, not
                                 `PolicyOutcome`, to avoid colliding with
                                 the unrelated v0.1.0
                                 `basis_core.policy.engine.PolicyOutcome`
                                 (a single-rule evaluation outcome, a
                                 different concept) — the same naming
                                 precedent Section 5 of the roadmap plan
                                 already applied to
                                 `OperationAwarePolicyRule`.
  OperationAwareFailureReason   Closed, six-value governed evaluator
                                 failure-category vocabulary — owned by
                                 `basis_core.decisions.operation_aware`
                                 (PR 27A), imported unchanged into this
                                 module (never redefined here). This
                                 module constructs only one member,
                                 `CONDITION_EVALUATION_ERROR`, today — see
                                 "Import boundary and vocabulary
                                 ownership" below for why `decisions` owns
                                 this shared vocabulary rather than
                                 `policy`, and "Scope boundary" for why the
                                 other five members are never produced
                                 here.

Architectural boundary — aggregation only, no orchestration
────────────────────────────────────────────────────────────────────────
This module implements exactly the combining semantics ADR-0002 §§4-7
assigns to the policy layer: evaluator-failure handling, deny precedence,
allow determination, default deny, and deterministic final reason
selection. Per `basis-architecture` ADR-0006, it does **not** implement the
`OperationAwareEvaluationEngine` — the future evaluation-owned orchestrator
(roadmap PR 27B, `src/basis_core/evaluation/operation_aware/engine.py`)
that will sequence applicability determination, candidate selection,
selector evaluation, and condition evaluation, and then call
`aggregate_policy_outcome` with their typed results. This module does not
determine bundle applicability (`applicability.py`, PR 17, reused as an
input here), does not select or match candidate rules (`selector.py`,
PR 19), does not evaluate conditions (`operators.py`/`condition_eval.py`,
PR 22-23), does not assemble a trace (`evaluation/operation_aware/
trace_assembly.py`, PR 26), does not assemble a response or audit evidence
(Milestone 10), and does not perform enforcement. It consumes already-
evaluated facts and produces one small, typed aggregation result.

Post-validation input only — this is not a second validation pipeline
────────────────────────────────────────────────────────────────────────
`aggregate_policy_outcome` assumes its caller has already run:

  - `validation.py`'s `validate_policy_bundle` (PR 15) on the bundle the
    evaluated rules were drawn from, so `rule_id` values are already
    unique within the bundle and every rule's shape is already valid;
  - `applicability.py`'s `determine_applicability` (PR 17) to produce the
    `bundle_applicability` argument;
  - `condition_eval.py`'s `evaluate_rule_conditions` (PR 22-23, via
    `selector.py`'s `evaluate_rule_selectors`, PR 19) once per candidate
    rule, to produce each `EvaluatedRule.result`.

This function performs no independent `rule_id` uniqueness check, no
bundle structural or semantic validation, and no selector or condition
evaluation of its own — doing any of that here would duplicate PR 15's,
PR 19's, or PR 22-23's already-established responsibility. A future
`OperationAwareEvaluationEngine` (PR 27B) is expected to prove, by
construction of its own call sequence, that validation always precedes
aggregation; this module does not and cannot enforce that itself, since it
never sees a raw or unvalidated `PolicyBundle`.

The one input-consistency check this module does perform — rejecting
`evaluated_rules` contributions paired with a `not_applicable` bundle
(`PolicyAggregationInputError`, see below) — is not bundle validation. It
is a caller-consistency guard on this function's own two-argument contract,
exactly analogous to `evaluation/operation_aware/trace_assembly.py`'s
`RuleIdentityMismatchError`: both reject an internally-inconsistent pair of
arguments without attempting to repair, prefer, or silently resolve it.

Required aggregation semantics
────────────────────────────────────────────────────────────────────────
1. **Evaluation failure is separate from authorization outcome, and its
   category is preserved, not discarded.** If any `EvaluatedRule.result`
   is `RuleConditionResult.ERROR` (already the approved condition-
   evaluation-failure signal established by PR 22-23's `condition_eval.py`
   — no new failure *input* vocabulary is introduced here), the result is
   `PolicyAggregationStatus.FAILED` with `outcome=None`, `reason_code=None`,
   and `failure_reason=OperationAwareFailureReason.CONDITION_EVALUATION_ERROR`.
   Failure is checked first, before deny precedence or allow determination,
   and dominates them unconditionally: a bundle with both a matched DENY
   rule and an unrelated errored rule is `failed`, never `deny`. The
   failure *category* is carried in the result precisely so a future
   `OperationAwareEvaluationEngine` (PR 27B) does not have to re-inspect
   `evaluated_rules` and re-derive it — see "Scope boundary" below.
2. **`not_applicable` bundle.** When `bundle_applicability` is
   `ApplicabilityResult.NOT_APPLICABLE`, the result is
   `OperationAwarePolicyOutcome.NOT_APPLICABLE` — never `deny` — with the
   fixed reason code `no_applicable_bundle` (the value already used by
   this repository's vendored `not-applicable` canonical-vector fixture,
   `tests/fixtures/basis-schemas/v0.2.0/compatibility/not-applicable/
   expected-evaluation-trace.yaml`). `evaluated_rules` must be empty in
   this case (see "Post-validation input only" above); a non-empty
   sequence paired with `not_applicable` raises
   `PolicyAggregationInputError`.
3. **Deny precedence.** For an applicable bundle, if any `EvaluatedRule`
   has `result=MATCHED` and `effect=RuleEffect.DENY`, the outcome is
   `OperationAwarePolicyOutcome.DENY` with reason code `deny_rule_matched`
   — regardless of how many `MATCHED` `ALLOW` rules are also present, and
   regardless of `evaluated_rules`' supplied order (deny precedence is
   computed with an order-independent `any()`, never a first-match scan).
4. **Allow determination.** For an applicable bundle with no matched DENY
   and at least one matched ALLOW, the outcome is
   `OperationAwarePolicyOutcome.ALLOW` with reason code
   `allow_rule_matched`.
5. **Default deny.** For an applicable bundle with no matched DENY and no
   matched ALLOW (including the empty-`evaluated_rules` case), the outcome
   is `OperationAwarePolicyOutcome.DENY` with reason code
   `no_allow_rule_matched` — deliberately a different reason code from
   explicit deny precedence's `deny_rule_matched`, so a consumer can
   always distinguish "a rule said deny" from "nothing said allow."
6. **Deterministic reason selection.** The reason code attached to a
   completed aggregation result is always one of the four fixed, generic
   codes above (`allow_rule_matched` / `deny_rule_matched` /
   `no_allow_rule_matched` / `no_applicable_bundle`) — the same values
   already used by this repository's five vendored canonical-vector
   fixtures. This module never copies a specific rule's own authored
   `reason_code` or `explanation` into the aggregation result: with
   multiple matched DENY (or multiple matched ALLOW) rules, there is no
   architecturally-authorized way to pick one rule's authored text over
   another's without inventing an unreviewed precedence order, so this
   module does not attempt to. A rule's own authored `reason_code`/
   `explanation` remains available to a future trace/response assembly
   stage through that rule's own `TraceRuleEvidence` entry (already
   preserved verbatim by `trace_assembly.py`'s `assemble_rule_evidence`,
   PR 26) — it is simply not what this module selects as the *aggregate*
   reason. This result carries no free-text explanation at all: composing
   a human-facing explanation string is response/trace-assembly work
   (Milestone 10), not an aggregation-semantics decision.

`failure_reason` vs. `reason_code` — two distinct fields, never substitutes
────────────────────────────────────────────────────────────────────────
`OperationAwareFailureReason` (`failure_reason`) is the **governed
evaluator failure category** — the closed, six-value vocabulary
(`invalid_request` / `unsupported_schema_version` / `invalid_policy_bundle`
/ `policy_validation_failure` / `condition_evaluation_error` /
`internal_evaluation_error`) that classifies *why evaluation could not
reach an authorization outcome at all*. `ReasonCode` (`reason_code`) is a
**machine-readable authorization explanation** — an open-format string
that explains *which completed authorization outcome was reached and
why* (`allow_rule_matched`, `deny_rule_matched`, `no_allow_rule_matched`,
`no_applicable_bundle`). These fields are never populated together and
neither substitutes for the other: a `FAILED` result has no authorization
outcome to explain, so `reason_code` is `None`; a `COMPLETED` result
reached a real outcome, not a failure, so `failure_reason` is `None`. See
"Required state invariants" on `PolicyAggregationResult`, below.

Scope boundary — this PR emits only `condition_evaluation_error`
────────────────────────────────────────────────────────────────────────
`OperationAwareFailureReason` is defined in `decisions/operation_aware.py`
as the full, closed, six-value shared vocabulary (see "Import boundary
and vocabulary ownership" below), but `aggregate_policy_outcome` itself
only ever *constructs* `CONDITION_EVALUATION_ERROR` — the one failure
category this function can genuinely determine from `evaluated_rules`. It
never constructs `INVALID_REQUEST`,
`UNSUPPORTED_SCHEMA_VERSION`, `INVALID_POLICY_BUNDLE`,
`POLICY_VALIDATION_FAILURE`, or `INTERNAL_EVALUATION_ERROR` — those
failure categories arise at other evaluation-pipeline stages (request
validation, bundle validation, internal errors) this function never sees
or reaches (per "Post-validation input only" above), and assigning them
here would mean guessing at a category this function has no evidence for.
Producing those five remaining categories is the future evaluation-owned
orchestrator's responsibility (PR 27B), not this PR's.

Import boundary and vocabulary ownership
────────────────────────────────────────────────────────────────────────
This module imports `basis_core.domain.operation_aware_vocabulary`
(`ReasonCode`, domain-owned, reused), `basis_core.decisions.
operation_aware` (`OperationAwareFailureReason`, decisions-owned, reused —
see below), and its own `policy/operation_aware/` siblings —
`applicability.ApplicabilityResult` (PR 17, reused as the
`bundle_applicability` parameter type), `condition_eval.RuleConditionResult`
(PR 22-23, reused as `EvaluatedRule.result`'s type), and
`rule.RuleEffect` (PR 13, reused as `EvaluatedRule.effect`'s type) — plus
the standard library. `decisions` is a legal import for `policy/`
(`docs/import-boundaries.md`: `policy/` may import `domain/` and
`decisions/`); this module does not import `basis_core.audit`,
`basis_core.evaluation`, `basis_core.adapters`, or `basis_core.enforcement`.

`OperationAwarePolicyOutcome` is a **policy-owned** three-value outcome
vocabulary, deliberately not imported from `basis_core.audit.
operation_aware.evaluation_trace.TraceOutcome` (which `policy/` may not
import) even though the two are parity-tested to carry the same three
string values. This mirrors this package's existing convention: `policy/`'s
`ApplicabilityResult` and `audit/`'s `TraceBundleApplicability` are two
independently-defined, value-parity-tested enums for the same reason; so
are `policy/`'s `RuleEffect` and `audit/`'s `TraceRuleEffect`. A future
`OperationAwareEvaluationEngine` (PR 27B, which legally imports both
`policy/` and `audit/` per ADR-0006) is expected to map
`OperationAwarePolicyOutcome` → `TraceOutcome` explicitly, the same way
`trace_assembly.py` already maps `RuleEffect` → `TraceRuleEffect` and
`RuleConditionResult` → `RuleResult`.

`OperationAwareFailureReason` is **not** policy-owned, and this module
does not define a second copy of it. It is a **shared, decisions-owned**
vocabulary (`basis_core.decisions.operation_aware.
OperationAwareFailureReason`, PR 27A) — `decisions` is the lowest common
legal dependency shared by every current and future consumer of this
vocabulary (policy-owned aggregation here; the future
`OperationAwareEvaluationEngine`, PR 27B; the future
`OperationAwareDecisionResponse`, PR 29; trace assembly's vocabulary
mapping, PR 26; response assembly, PR 31; audit-evidence assembly,
Milestone 10) — see `decisions/operation_aware.py`'s own docstring,
"Shared evaluation-result vocabulary ownership", for the full rationale
and the alternatives that were rejected (this module defining it and
`audit`/`evaluation` importing `policy`, which is not permitted; this
module importing it from `audit/operation_aware/evaluation_trace.
TraceFailureReason` directly, which is also not permitted — `policy/` may
not import `audit/`, enforced by this package's recursive import-boundary
guard, `tests/test_import_boundaries.py::
test_policy_operation_aware_does_not_import_a_forbidden_layer`).
`TraceFailureReason` (PR 25) remains audit's own, independently-defined,
value- and member-name-parity-tested local copy of the same six values —
unmoved and unchanged by this decision; see `decisions/operation_aware.
py`'s "Audit separation" section. A future `OperationAwareEvaluationEngine`
(PR 27B) is expected to map `OperationAwareFailureReason` →
`TraceFailureReason` explicitly where a trace-shaped representation is
needed, the same way it is expected to map `OperationAwarePolicyOutcome` →
`TraceOutcome`.

Purity
────────────────────────────────────────────────────────────────────────
`aggregate_policy_outcome` reads `bundle_applicability` and
`evaluated_rules` only; it never mutates either. It performs no I/O, no
network access, no clock access, and no random-value access. It generates
no identifier and copies no raw request, rule, or policy content —
`EvaluatedRule` carries only a rule's stable identity, its authored effect,
and its already-computed condition-evaluation result, never the rule's
`match`/`conditions`/`reason_code`/`explanation` or any request field.
Identical typed inputs always produce an equal `PolicyAggregationResult`;
the result's fields do not depend on `evaluated_rules`' iteration order
(both dominance checks below are order-independent `any()` scans, not
first-match scans), on wall-clock time, on call count, or on any other
mutable external state. Constructing or calling this module has no
observable effect on any `basis_core.policy.engine.PolicyEngine` instance
— no shared mutable state exists between the v0.1.0 kernel and this
module.

Not implemented by this module (deferred to later, separately-scoped
roadmap PRs): the `OperationAwareEvaluationEngine` orchestration sequence
itself (PR 27B, `src/basis_core/evaluation/operation_aware/engine.py`);
canonical-vector-shaped unit tests wired through the full stack (PR 28);
trace assembly (already implemented, PR 26, upstream of this module in the
sense that it consumes different, non-overlapping evidence — see "no
audit/evaluation import" above); response and `AuditEvidence` assembly
(Milestone 10); `OperationAwareEnforcementPoint` integration (Milestone 11);
production of any `OperationAwareFailureReason` member other than
`CONDITION_EVALUATION_ERROR` — see "Scope boundary" above.

Public API status: internal to the operation-aware package for now,
exactly like `condition.py` (PR 12), `rule.py` (PR 13), `bundle.py`
(PR 14), `validation.py` (PR 15), and `applicability.py` (PR 17). Not
re-exported from `basis_core.policy` or any other package `__init__.py`;
see `docs/public-api.md`'s "Open API questions" convention and Section 6
of the roadmap plan for when operation-aware symbols are expected to
graduate to the stable public API (Milestone 11, PR 35).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum

from basis_core.decisions.operation_aware import OperationAwareFailureReason
from basis_core.domain.operation_aware_vocabulary import ReasonCode
from basis_core.policy.operation_aware.applicability import ApplicabilityResult
from basis_core.policy.operation_aware.condition_eval import RuleConditionResult
from basis_core.policy.operation_aware.rule import RuleEffect

__all__ = [
    "EvaluatedRule",
    "OperationAwarePolicyOutcome",
    "PolicyAggregationInputError",
    "PolicyAggregationResult",
    "PolicyAggregationStatus",
    "aggregate_policy_outcome",
]


# ══════════════════════════════════════════════════════════════════════════
# Fixed, generic aggregation-level reason codes (Semantics 2-6 above)
# ══════════════════════════════════════════════════════════════════════════
#
# These four values are not invented by this module: they are the exact
# aggregate-level `reason_code` strings already used by this repository's
# vendored canonical-vector fixtures
# (`tests/fixtures/basis-schemas/v0.2.0/compatibility/*/
# expected-evaluation-trace.yaml`) for the `allow-basic`, `deny-precedence`,
# `default-deny`, and `not-applicable` scenarios respectively. Reusing them
# here, as fixed constants rather than caller-suppliable strings, is what
# makes reason-code selection deterministic and precedence-free — see this
# module's docstring, point 6.

_REASON_ALLOW_RULE_MATCHED = ReasonCode("allow_rule_matched")
_REASON_DENY_RULE_MATCHED = ReasonCode("deny_rule_matched")
_REASON_NO_ALLOW_RULE_MATCHED = ReasonCode("no_allow_rule_matched")
_REASON_NO_APPLICABLE_BUNDLE = ReasonCode("no_applicable_bundle")


# ══════════════════════════════════════════════════════════════════════════
# Result vocabularies
# ══════════════════════════════════════════════════════════════════════════


class PolicyAggregationStatus(str, Enum):
    """
    Closed, two-value vocabulary distinguishing a completed aggregation
    from one that could not be completed.

    COMPLETED   Every evaluated rule was itself evaluable (no
                `RuleConditionResult.ERROR`); `PolicyAggregationResult.
                outcome` and `.reason_code` are both non-`None`, and
                `.failure_reason` is `None`.
    FAILED      At least one evaluated rule's condition evaluation could
                not be completed. `PolicyAggregationResult.outcome` and
                `.reason_code` are both `None` — a failed aggregation never
                carries a substantive authorization outcome or a reason
                for one — and `.failure_reason` is non-`None`, carrying the
                governed failure category, per this module's docstring,
                Semantics 1.
    """

    COMPLETED = "completed"
    FAILED = "failed"


class OperationAwarePolicyOutcome(str, Enum):
    """
    Closed, three-value, policy-owned authorization-outcome vocabulary.

    ALLOW            At least one matched `ALLOW` rule, no matched `DENY`
                     rule, in an applicable bundle.
    DENY             Either a matched `DENY` rule (deny precedence) or no
                     matched rule of either effect (default deny), in an
                     applicable bundle. `PolicyAggregationResult.reason_code`
                     distinguishes the two cases.
    NOT_APPLICABLE   The bundle's declared scope did not cover the request
                     at all (`ApplicabilityResult.NOT_APPLICABLE`); no rule
                     was ever a candidate.

    See this module's docstring, "Import boundary and vocabulary
    ownership", for why this is a distinct, policy-owned type rather than
    an import of `basis_core.audit.operation_aware.evaluation_trace.
    TraceOutcome`.
    """

    ALLOW = "allow"
    DENY = "deny"
    NOT_APPLICABLE = "not_applicable"


class PolicyAggregationInputError(ValueError):
    """
    Raised by `aggregate_policy_outcome` when its two arguments are
    mutually inconsistent: `bundle_applicability` is
    `ApplicabilityResult.NOT_APPLICABLE` but `evaluated_rules` is
    non-empty.

    This is a caller-input-consistency error, not an authorization outcome
    — analogous to `evaluation/operation_aware/trace_assembly.py`'s
    `RuleIdentityMismatchError`. A non-applicable bundle has, by
    definition, no candidate rules (see `applicability.py`'s own
    docstring: an `applicable`/`not_applicable` classification is made
    without inspecting `bundle.rules` at all); a caller that supplies rule
    facts alongside a `not_applicable` classification has therefore
    already produced an internally-inconsistent pair of arguments, and this
    function refuses to silently ignore the contradiction by discarding
    either input.
    """


# ══════════════════════════════════════════════════════════════════════════
# Already-evaluated rule fact
# ══════════════════════════════════════════════════════════════════════════


@dataclass(frozen=True, slots=True)
class EvaluatedRule:
    """
    The smallest immutable, policy-owned fact `aggregate_policy_outcome`
    needs about one already-evaluated candidate rule.

      rule_id   The rule's stable identifier — carried for caller
                traceability only; this module performs no uniqueness
                check of its own (see the module docstring, "Post-
                validation input only") and does not use `rule_id` in any
                aggregation decision.
      effect    The rule's authored `RuleEffect` (`ALLOW`/`DENY`), taken
                from `OperationAwarePolicyRule.effect` unchanged.
      result    The rule's aggregate `RuleConditionResult`
                (`MATCHED`/`NOT_MATCHED`/`ERROR`), taken from
                `condition_eval.RuleConditionEvaluation.result` unchanged
                — already the approved three-value vocabulary combining
                structural match-criteria evaluation (PR 19) with
                condition evaluation (PR 22-23); this module introduces no
                new failure or match vocabulary.

    Carries no raw rule content (`match`, `conditions`, `reason_code`,
    `explanation`), no per-condition detail, and no request content of any
    kind — only the three facts aggregation actually needs.
    """

    rule_id: str
    effect: RuleEffect
    result: RuleConditionResult


# ══════════════════════════════════════════════════════════════════════════
# Aggregation result
# ══════════════════════════════════════════════════════════════════════════


@dataclass(frozen=True, slots=True)
class PolicyAggregationResult:
    """
    Immutable, deterministic result of `aggregate_policy_outcome` — an
    evaluation status, an authorization outcome, a failure reason, and a
    final reason code.

      status          `PolicyAggregationStatus.COMPLETED` or `.FAILED`.
      outcome         `OperationAwarePolicyOutcome.ALLOW` / `.DENY` /
                      `.NOT_APPLICABLE` when `status` is `COMPLETED`;
                      always `None` when `status` is `FAILED`.
      failure_reason  `OperationAwareFailureReason.CONDITION_EVALUATION_ERROR`
                      (the only member this PR constructs — see the module
                      docstring, "Scope boundary") when `status` is
                      `FAILED`; always `None` when `status` is `COMPLETED`.
                      The governed evaluator failure *category* — see the
                      module docstring, "`failure_reason` vs. `reason_code`",
                      for how this differs from `reason_code`.
      reason_code     One of this module's four fixed, generic `ReasonCode`
                      values when `status` is `COMPLETED`; always `None`
                      when `status` is `FAILED` (see the module docstring,
                      Semantics 1 and 6). The machine-readable authorization
                      *explanation* — never a substitute for
                      `failure_reason`, and never substituted by it.

    Construction-time invariant (enforced defensively below, not merely by
    convention — `aggregate_policy_outcome` is this type's only intended
    constructor, but a future caller must not be able to build an
    inconsistent result by hand):

        COMPLETED:  outcome is non-None, reason_code is non-None,
                    failure_reason is None
        FAILED:     outcome is None, reason_code is None,
                    failure_reason is non-None

    Every contradictory combination is rejected — including a `COMPLETED`
    result carrying a non-`None` `failure_reason`, and a `FAILED` result
    carrying a non-`None` `outcome` or `reason_code`.

    Free of serialization responsibilities, raw request or policy content,
    timestamps, generated identifiers, exception objects, and arbitrary
    metadata — see the module docstring, "Purity".
    """

    status: PolicyAggregationStatus
    outcome: OperationAwarePolicyOutcome | None
    failure_reason: OperationAwareFailureReason | None
    reason_code: ReasonCode | None

    def __post_init__(self) -> None:
        if self.status is PolicyAggregationStatus.FAILED:
            if self.outcome is not None:
                raise ValueError(
                    "PolicyAggregationResult.outcome must be None when status is "
                    "'failed'; a failed aggregation never carries a substantive "
                    "authorization outcome."
                )
            if self.reason_code is not None:
                raise ValueError(
                    "PolicyAggregationResult.reason_code must be None when status is "
                    "'failed'; a failed aggregation never carries a reason for an "
                    "outcome it did not reach."
                )
            if self.failure_reason is None:
                raise ValueError(
                    "PolicyAggregationResult.failure_reason must not be None when "
                    "status is 'failed'; a failed aggregation must always carry the "
                    "governed evaluator failure category it failed with."
                )
        else:
            if self.outcome is None:
                raise ValueError(
                    "PolicyAggregationResult.outcome must not be None when status is 'completed'."
                )
            if self.reason_code is None:
                raise ValueError(
                    "PolicyAggregationResult.reason_code must not be None when status "
                    "is 'completed'."
                )
            if self.failure_reason is not None:
                raise ValueError(
                    "PolicyAggregationResult.failure_reason must be None when status is "
                    "'completed'; a completed aggregation reached a real outcome, not a "
                    "failure, so it carries no failure category."
                )


# ══════════════════════════════════════════════════════════════════════════
# Public entry point
# ══════════════════════════════════════════════════════════════════════════


def aggregate_policy_outcome(
    bundle_applicability: ApplicabilityResult,
    evaluated_rules: Sequence[EvaluatedRule],
) -> PolicyAggregationResult:
    """
    Determine the final, deterministic policy evaluation result from a
    bundle's applicability and an ordered set of already-evaluated rule
    facts.

    See the module docstring for the full semantics (evaluator-failure
    handling, `not_applicable`, deny precedence, allow determination,
    default deny, deterministic reason selection) and for what this
    function assumes has already run (`validate_policy_bundle`,
    `determine_applicability`, `evaluate_rule_conditions`).

    Args:
        bundle_applicability: the bundle's already-determined
            `ApplicabilityResult` (`applicability.determine_applicability`,
            PR 17).
        evaluated_rules: already-evaluated rule facts, one `EvaluatedRule`
            per candidate rule considered, in any order — this function's
            result never depends on this sequence's order. Must be empty
            when `bundle_applicability` is `NOT_APPLICABLE`.

    Returns:
        A `PolicyAggregationResult` — `FAILED` (no outcome, no reason_code,
        `failure_reason=CONDITION_EVALUATION_ERROR`) if any evaluated rule
        could not be evaluated; otherwise `COMPLETED` (no failure_reason)
        with `NOT_APPLICABLE`, `DENY` (precedence or default), or `ALLOW`.

    Raises:
        PolicyAggregationInputError: if `bundle_applicability` is
            `NOT_APPLICABLE` and `evaluated_rules` is non-empty.
    """
    if bundle_applicability is ApplicabilityResult.NOT_APPLICABLE:
        if evaluated_rules:
            raise PolicyAggregationInputError(
                "aggregate_policy_outcome received a non-empty evaluated_rules "
                f"({len(evaluated_rules)} entr{'y' if len(evaluated_rules) == 1 else 'ies'}) "
                "alongside bundle_applicability=NOT_APPLICABLE; a non-applicable "
                "bundle has no candidate rules, so this pairing is internally "
                "inconsistent and is refused rather than silently resolved."
            )
        return PolicyAggregationResult(
            status=PolicyAggregationStatus.COMPLETED,
            outcome=OperationAwarePolicyOutcome.NOT_APPLICABLE,
            failure_reason=None,
            reason_code=_REASON_NO_APPLICABLE_BUNDLE,
        )

    # Semantics 1 — evaluation failure is checked first and dominates deny
    # precedence and allow determination unconditionally. The only failure
    # category this function can determine from evaluated_rules is
    # condition_evaluation_error — see the module docstring, "Scope
    # boundary".
    if any(rule.result is RuleConditionResult.ERROR for rule in evaluated_rules):
        return PolicyAggregationResult(
            status=PolicyAggregationStatus.FAILED,
            outcome=None,
            failure_reason=OperationAwareFailureReason.CONDITION_EVALUATION_ERROR,
            reason_code=None,
        )

    # Semantics 3 — deny precedence. Order-independent: a matched DENY rule
    # anywhere in evaluated_rules produces DENY, regardless of how many
    # matched ALLOW rules are also present or where either appears in the
    # supplied sequence.
    deny_matched = any(
        rule.result is RuleConditionResult.MATCHED and rule.effect is RuleEffect.DENY
        for rule in evaluated_rules
    )
    if deny_matched:
        return PolicyAggregationResult(
            status=PolicyAggregationStatus.COMPLETED,
            outcome=OperationAwarePolicyOutcome.DENY,
            failure_reason=None,
            reason_code=_REASON_DENY_RULE_MATCHED,
        )

    # Semantics 4 — allow determination: no matched DENY, at least one
    # matched ALLOW.
    allow_matched = any(
        rule.result is RuleConditionResult.MATCHED and rule.effect is RuleEffect.ALLOW
        for rule in evaluated_rules
    )
    if allow_matched:
        return PolicyAggregationResult(
            status=PolicyAggregationStatus.COMPLETED,
            outcome=OperationAwarePolicyOutcome.ALLOW,
            failure_reason=None,
            reason_code=_REASON_ALLOW_RULE_MATCHED,
        )

    # Semantics 5 — default deny: no matched DENY, no matched ALLOW
    # (including the case where evaluated_rules is empty).
    return PolicyAggregationResult(
        status=PolicyAggregationStatus.COMPLETED,
        outcome=OperationAwarePolicyOutcome.DENY,
        failure_reason=None,
        reason_code=_REASON_NO_ALLOW_RULE_MATCHED,
    )
