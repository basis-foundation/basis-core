"""
basis_core.evaluation.operation_aware.response_assembly — pure, deterministic
`OperationAwareDecisionResponse`/`AuditEvidence` assembly from an
already-produced `EvaluationTrace`.

This is the fourth module added under `src/basis_core/evaluation/
operation_aware/` (see
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`, Milestone 10,
PR 31 — "Response + AuditEvidence assembly"), after PR 26's
`trace_assembly.py`, PR 27B's `engine.py`, and PR 29's `response.py`. It
converts already-determined evaluation facts, carried by an already-validated
`EvaluationTrace` (`OperationAwareEvaluationEngine.evaluate()`'s return
value), into two published, bounded, kernel-side artifacts:

  assemble_operation_aware_decision_response(...)
      Builds one `OperationAwareDecisionResponse` (PR 29) from one
      `EvaluationTrace` (PR 25).
  assemble_audit_evidence(...)
      Builds one `AuditEvidence` (PR 30) from one `OperationAwareDecisionRequest`
      (PR 8) and one `EvaluationTrace`, plus a caller-supplied evidence
      identifier and recording timestamp.

What this module does not do
──────────────────────────────
It does not evaluate policy, invoke `OperationAwareEvaluationEngine`, call any
policy-owned applicability/selection/condition/aggregation operation,
reinterpret or recompute an authorization outcome, persist audit evidence,
enforce a decision, construct a `GatewayAuditEvent`, or implement the full
response/trace/audit-evidence agreement matrix (that remains PR 32). Both
functions treat `trace` as the single, already-authoritative source of every
final evaluation fact — `evaluation_status`, `outcome`, `failure_reason`,
`bundle_id`, `bundle_version`, `reason_code`, `explanation`, `request_id`,
`correlation_id`, and `trace_id` — and never accept a second, independently
supplied value for any of them. Accepting duplicate values for facts the
trace already carries would permit a caller to construct a response or audit
record that contradicts the trace that is supposed to explain it.

Why no `policy/` import is needed
────────────────────────────────────
`EvaluationTrace` (produced by `OperationAwareEvaluationEngine.evaluate()`,
PR 27B) already contains every already-determined evaluation fact this module
needs: final `evaluation_status`/`outcome`/`failure_reason`, bundle identity,
`reason_code`, `explanation`, and the complete ordered `rule_evidence` this
module projects `matched_rule_ids` from. No policy-owned type or operation is
needed to assemble either artifact, so this module imports nothing from
`basis_core.policy`.

Vocabulary mapping — audit-owned trace vocabulary to decisions-owned
response/audit-evidence vocabulary
──────────────────────────────────────────────────────────────────────
`EvaluationTrace` uses audit-owned local vocabulary
(`basis_core.audit.operation_aware.evaluation_trace.EvaluationStatus`/
`.TraceOutcome`/`.TraceFailureReason`), independently defined there because
`audit/` may import only `domain/` and `decisions/`
(`docs/import-boundaries.md`). `OperationAwareDecisionResponse` and
`AuditEvidence` both instead use the decisions-owned vocabulary
(`basis_core.decisions.operation_aware.OperationAwareEvaluationStatus`/
`.OperationAwareDecisionOutcome`/`.OperationAwareFailureReason`). This module
is the first to actually convert between the two families at runtime, via
three explicit, exhaustive mapping tables — never `TargetEnum(source.value)`
value-coercion, never a dict/`Any`/`cast` bypass, and never a guessed
fallback. A completeness test (`tests/operation_aware/
test_response_assembly.py`) walks both the source and target enum
memberships for every table and asserts exact set equality, so an enum
member added to either vocabulary without a reviewed update to the matching
table fails loudly rather than silently mapping through a coincidental string
match.

Response trace-reference/embedding design
─────────────────────────────────────────────
`assemble_operation_aware_decision_response` always sets `trace_id` from
`trace.trace_id` — every response identifies the trace that explains it, by
identifier, unconditionally. Whether the full `EvaluationTrace` is also
*embedded* (`response.evaluation_trace`) is controlled by the caller-supplied,
required `embed_evaluation_trace: bool` keyword argument: `True` embeds
`trace` unchanged; `False` leaves `evaluation_trace` `None` (reference-only).
No inference from environment, configuration, or trace content is performed,
and no alternation between the two shapes happens except by this one explicit
caller choice.

This mirrors the vendored `basis-schemas` v0.2.1 canonical compatibility
artifacts directly: every one of the five scenarios' `expected-operation-
aware-decision-response.yaml` fixtures (`tests/fixtures/basis-schemas/
v0.2.1/compatibility/*/expected-operation-aware-decision-response.yaml`)
carries `trace_id` and omits `evaluation_trace` entirely — reference-only is
the canonical shape a caller reaches by passing `embed_evaluation_trace=False`.
The published `operation-aware-decision-response` contract's own prose
(`operation-aware-decision-response.yaml`, referenced by `response.py`'s own
docstring) documents both an optional trace reference and an optional
embedded trace as legal; this module does not foreclose the embedded shape
(a caller with a reason to embed passes `True`), it only refuses to guess
which one a caller wants.

Request/trace identity safety (`assemble_audit_evidence` only)
────────────────────────────────────────────────────────────────
`assemble_audit_evidence` is the one function in this module that combines
request-owned data (the typed evidence references,
`identity_evidence_reference`/`adapter_evidence_reference`) with trace-owned
evaluation facts. Before doing so, it checks `request.request_id ==
trace.request_id` and `request.correlation_id == trace.correlation_id` by
exact equality (including `None`) and raises
`EvaluationArtifactIdentityMismatchError` — naming only the mismatched field,
never dumping raw request content — if either check fails. This protects
against combining a trace produced for one request with evidence references
that belong to a different request; it is a narrow input-identity guard, not
the complete response/trace/audit-evidence agreement matrix PR 32 owns.

Matched-rule projection
─────────────────────────
`AuditEvidence.matched_rule_ids` is derived, not requested from the caller:
this module walks `trace.rule_evidence` in its own already-established order
and includes exactly the `rule_id` of every entry whose `rule_result` is
`RuleResult.MATCHED` — never `not_matched`, `skipped`, or `error`. Order is
preserved exactly as `trace.rule_evidence` already orders it; this module
never sorts or deduplicates (`EvaluationTrace`'s own construction-time
invariant already guarantees `rule_id` uniqueness within `rule_evidence`,
so no rule_id can appear twice in the projection). When no rule evidence
entry matched, the projection is an empty list — `AuditEvidence.
matched_rule_ids` is `list[str] = Field(default_factory=list)` with no
non-empty constraint, so an empty list (not `None`, which the field does not
accept) is the model-correct absence value; this matches every vendored
`default-deny`/`not-applicable` canonical `expected-audit-evidence.yaml`
fixture, both of which publish `matched_rule_ids: []`.

Caller-supplied `evidence_id`/`recorded_at` — no generation
────────────────────────────────────────────────────────────
`evidence_id` and `recorded_at` are supplied by the caller and preserved
exactly; this module has no default factory, no clock access
(`datetime.now`/`datetime.utcnow` are never called), no UUID generation, no
random-value source, and no environment/filesystem/network/database access
of any kind.

Purity and determinism
────────────────────────
Both public functions are synchronous, side-effect-free, deterministic, and
stateless: they read their arguments only, never mutate the request, the
trace, any nested rule/condition-evidence entry, or any evidence-reference
model, and hold no module-level mutable state (the mapping tables below are
plain, immutable `dict` literals). Equal inputs always produce equal outputs.

Import boundary
────────────────
This module imports from `basis_core.audit.operation_aware.evaluation_trace`
(`EvaluationTrace` and its local vocabulary), `basis_core.audit.
operation_aware.trace_rule_evidence` (`RuleResult`, for matched-rule
projection), `basis_core.audit.operation_aware.audit_evidence`
(`AuditEvidence`), `basis_core.decisions.operation_aware`
(`OperationAwareDecisionRequest` and the decisions-owned shared vocabulary),
and its own sibling `basis_core.evaluation.operation_aware.response`
(`OperationAwareDecisionResponse`) — all legal per `docs/import-
boundaries.md` (`evaluation/` may import `domain/`, `decisions/`, `policy/`,
and `audit/`, and its own siblings). It does not import `basis_core.policy`
(see "Why no `policy/` import is needed" above), `basis_core.adapters`, or
`basis_core.enforcement`. The existing recursive guard,
`tests/test_import_boundaries.py::
test_evaluation_operation_aware_does_not_import_from_adapters_or_enforcement`,
already covers this module (it scans `evaluation/operation_aware/`
recursively) — no new boundary test is added for this PR.

Public API status: internal to the operation-aware package, exactly like
every other operation-aware module added so far. Not re-exported from
`basis_core.evaluation`, `basis_core`, or any other package `__init__.py`;
public API stabilization remains Milestone 11, PR 35.
"""

from __future__ import annotations

from datetime import datetime

from basis_core.audit.operation_aware.audit_evidence import AuditEvidence
from basis_core.audit.operation_aware.evaluation_trace import (
    EvaluationStatus,
    EvaluationTrace,
    TraceFailureReason,
    TraceOutcome,
)
from basis_core.audit.operation_aware.trace_rule_evidence import RuleResult
from basis_core.decisions.operation_aware import (
    OperationAwareDecisionOutcome,
    OperationAwareDecisionRequest,
    OperationAwareEvaluationStatus,
    OperationAwareFailureReason,
)
from basis_core.evaluation.operation_aware.response import OperationAwareDecisionResponse

__all__ = [
    "EvaluationArtifactIdentityMismatchError",
    "assemble_audit_evidence",
    "assemble_operation_aware_decision_response",
]


class EvaluationArtifactIdentityMismatchError(ValueError):
    """
    Raised by `assemble_audit_evidence` when the caller-supplied
    `OperationAwareDecisionRequest` and `EvaluationTrace` do not identify the
    same evaluation — either `request.request_id != trace.request_id` or
    `request.correlation_id != trace.correlation_id` (exact equality,
    including `None`).

    This is a caller-input-consistency error, not an authorization outcome:
    it signals that the two arguments describe different evaluations, which
    this module refuses to resolve by silently combining a trace from one
    request with evidence references from another. The message names only
    the mismatched field and the two identifier values under comparison —
    never the request's evidence references, context objects, or any other
    request content — mirroring `trace_assembly.RuleIdentityMismatchError`'s
    own "identify, don't dump" convention.
    """


# ══════════════════════════════════════════════════════════════════════════
# Explicit, exhaustive vocabulary mappings (audit-owned trace vocabulary →
# decisions-owned response/audit-evidence vocabulary)
# ══════════════════════════════════════════════════════════════════════════
#
# Each table is a plain `dict` keyed by every member of its source enum,
# never a `.value`-string coercion (`TargetEnum(source.value)`) and never a
# fallback/default branch. `tests/operation_aware/test_response_assembly.py`
# walks each source and target enum and asserts exact set-equality against
# these tables, so an enum member added to either vocabulary without a
# reviewed update here fails that test loudly rather than silently mapping
# through a coincidental string match.

_EVALUATION_STATUS_TO_RESPONSE_STATUS: dict[EvaluationStatus, OperationAwareEvaluationStatus] = {
    EvaluationStatus.COMPLETED: OperationAwareEvaluationStatus.COMPLETED,
    EvaluationStatus.FAILED: OperationAwareEvaluationStatus.FAILED,
}

_TRACE_OUTCOME_TO_RESPONSE_OUTCOME: dict[TraceOutcome, OperationAwareDecisionOutcome] = {
    TraceOutcome.ALLOW: OperationAwareDecisionOutcome.ALLOW,
    TraceOutcome.DENY: OperationAwareDecisionOutcome.DENY,
    TraceOutcome.NOT_APPLICABLE: OperationAwareDecisionOutcome.NOT_APPLICABLE,
}

_TRACE_FAILURE_REASON_TO_RESPONSE_FAILURE_REASON: dict[
    TraceFailureReason, OperationAwareFailureReason
] = {
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
    """Explicit table lookup — never `.value` coercion."""
    return _EVALUATION_STATUS_TO_RESPONSE_STATUS[status]


def _map_outcome(outcome: TraceOutcome | None) -> OperationAwareDecisionOutcome | None:
    """`None` passes through unchanged (a failed evaluation's null outcome
    is never looked up); any non-`None` value is mapped through the explicit
    table."""
    if outcome is None:
        return None
    return _TRACE_OUTCOME_TO_RESPONSE_OUTCOME[outcome]


def _map_failure_reason(
    failure_reason: TraceFailureReason | None,
) -> OperationAwareFailureReason | None:
    """`None` passes through unchanged (a completed evaluation's null
    failure_reason is never looked up); any non-`None` value is mapped
    through the explicit table."""
    if failure_reason is None:
        return None
    return _TRACE_FAILURE_REASON_TO_RESPONSE_FAILURE_REASON[failure_reason]


# ══════════════════════════════════════════════════════════════════════════
# Matched-rule projection
# ══════════════════════════════════════════════════════════════════════════


def _project_matched_rule_ids(trace: EvaluationTrace) -> list[str]:
    """
    Derive `AuditEvidence.matched_rule_ids` from `trace.rule_evidence`: the
    `rule_id` of every entry whose `rule_result` is `RuleResult.MATCHED`,
    in `rule_evidence`'s own already-established order. Never sorted, never
    deduplicated (uniqueness is already guaranteed by `EvaluationTrace`'s
    own construction-time invariant), and never inferred from `trace.outcome`
    alone — a `deny` outcome may carry both a matched allow and a matched
    deny rule (deny precedence); this function reports both, honestly.
    """
    return [
        entry.rule_id for entry in trace.rule_evidence if entry.rule_result is RuleResult.MATCHED
    ]


# ══════════════════════════════════════════════════════════════════════════
# Request/trace identity safety
# ══════════════════════════════════════════════════════════════════════════


def _check_identity_agreement(
    *, request: OperationAwareDecisionRequest, trace: EvaluationTrace
) -> None:
    if request.request_id != trace.request_id:
        raise EvaluationArtifactIdentityMismatchError(
            "assemble_audit_evidence received a request and a trace with disagreeing "
            f"request_id values: request.request_id={request.request_id!r}, "
            f"trace.request_id={trace.request_id!r}. Refusing to combine evidence "
            "references from one request with evaluation facts from a different "
            "evaluation."
        )
    if request.correlation_id != trace.correlation_id:
        raise EvaluationArtifactIdentityMismatchError(
            "assemble_audit_evidence received a request and a trace with disagreeing "
            f"correlation_id values: request.correlation_id={request.correlation_id!r}, "
            f"trace.correlation_id={trace.correlation_id!r}. Refusing to combine "
            "evidence references from one request with evaluation facts from a "
            "different evaluation."
        )


# ══════════════════════════════════════════════════════════════════════════
# Response assembly
# ══════════════════════════════════════════════════════════════════════════


def assemble_operation_aware_decision_response(
    *,
    trace: EvaluationTrace,
    embed_evaluation_trace: bool,
) -> OperationAwareDecisionResponse:
    """
    Assemble one `OperationAwareDecisionResponse` from one already-produced
    `EvaluationTrace`.

    Every field is copied or explicitly mapped from `trace` — none is
    generated, recalculated, or independently supplied by this function's
    caller. `trace_id` is always set from `trace.trace_id`. Whether the full
    trace is also embedded (`response.evaluation_trace`) is controlled
    exclusively by `embed_evaluation_trace` — see this module's docstring,
    "Response trace-reference/embedding design," for why this explicit,
    caller-chosen behavior was selected over an inferred one.

    This function does not invoke `OperationAwareEvaluationEngine`, does not
    call any policy-owned operation, and does not inspect `trace.rule_evidence`
    to redetermine `trace.outcome` — `trace`'s already-validated final state
    is authoritative input, not a candidate for re-evaluation.

    Args:
        trace: an already-constructed, already-validated `EvaluationTrace`
            (typically `OperationAwareEvaluationEngine.evaluate()`'s return
            value).
        embed_evaluation_trace: `True` to embed `trace` unchanged as
            `response.evaluation_trace`; `False` to leave it `None`
            (reference-only, via `trace_id`).

    Returns:
        A validated `OperationAwareDecisionResponse` (constructed through
        normal Pydantic validation — never `model_construct`).
    """
    return OperationAwareDecisionResponse(
        request_id=trace.request_id,
        correlation_id=trace.correlation_id,
        evaluation_status=_map_evaluation_status(trace.evaluation_status),
        outcome=_map_outcome(trace.outcome),
        failure_reason=_map_failure_reason(trace.failure_reason),
        bundle_id=trace.bundle_id,
        bundle_version=trace.bundle_version,
        trace_id=trace.trace_id,
        evaluation_trace=trace if embed_evaluation_trace else None,
        reason_code=trace.reason_code,
        explanation=trace.explanation,
    )


# ══════════════════════════════════════════════════════════════════════════
# AuditEvidence assembly
# ══════════════════════════════════════════════════════════════════════════


def assemble_audit_evidence(
    *,
    request: OperationAwareDecisionRequest,
    trace: EvaluationTrace,
    evidence_id: str,
    recorded_at: datetime,
) -> AuditEvidence:
    """
    Assemble one `AuditEvidence` from the `OperationAwareDecisionRequest`
    that was evaluated, the `EvaluationTrace` that resulted, and two
    caller-supplied values this module never generates.

    Before combining `request`'s typed evidence references with `trace`'s
    evaluation facts, this function verifies `request.request_id ==
    trace.request_id` and `request.correlation_id == trace.correlation_id`
    (exact equality, including `None`) and raises
    `EvaluationArtifactIdentityMismatchError` if either disagrees — see this
    module's docstring, "Request/trace identity safety."

    `evidence_id` and `recorded_at` are preserved exactly as supplied; this
    function calls no clock, generates no identifier, and uses no
    randomness. `matched_rule_ids` is derived from `trace.rule_evidence` —
    see this module's docstring, "Matched-rule projection" — never accepted
    as a separate argument. `identity_evidence_reference`/
    `adapter_evidence_reference` are copied from `request` as the real typed
    models (never reconstructed from a dict); this function does not fetch,
    resolve, or verify the evidence either one references.

    Args:
        request: the already-constructed, already-validated
            `OperationAwareDecisionRequest` that `trace` is the evaluation
            result of.
        trace: an already-constructed, already-validated `EvaluationTrace`
            for the same evaluation as `request`.
        evidence_id: caller-supplied, stable identifier for this audit
            evidence record. Never generated by this function.
        recorded_at: caller-supplied, timezone-aware timestamp of when this
            record was produced. Never derived from a clock or from any
            other field.

    Returns:
        A validated `AuditEvidence` (constructed through normal Pydantic
        validation — never `model_construct`).

    Raises:
        EvaluationArtifactIdentityMismatchError: if `request` and `trace` do
            not identify the same evaluation.
    """
    _check_identity_agreement(request=request, trace=trace)

    return AuditEvidence(
        evidence_id=evidence_id,
        request_id=trace.request_id,
        correlation_id=trace.correlation_id,
        trace_id=trace.trace_id,
        evaluation_status=_map_evaluation_status(trace.evaluation_status),
        outcome=_map_outcome(trace.outcome),
        failure_reason=_map_failure_reason(trace.failure_reason),
        bundle_id=trace.bundle_id,
        bundle_version=trace.bundle_version,
        matched_rule_ids=_project_matched_rule_ids(trace),
        identity_evidence_reference=request.identity_evidence_reference,
        adapter_evidence_reference=request.adapter_evidence_reference,
        reason_code=trace.reason_code,
        explanation=trace.explanation,
        recorded_at=recorded_at,
    )
