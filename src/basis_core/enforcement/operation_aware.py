"""
basis_core.enforcement.operation_aware — `OperationAwareEnforcementPoint`,
the operation-aware enforcement surface.

This module implements `docs/adr/ADR-0006-operation-aware-enforcement-point.md`
(roadmap PR 34, `docs/implementation/basis-core-v0.2-operation-aware-plan.md`,
Milestone 11). It is a new, additive sibling of
`basis_core.enforcement.enforcement.EnforcementPoint` — it does not modify,
subclass, or share implementation with that class (ADR-0006 Decision 1).

  EnforcementDisposition           Closed, two-value (`allow`/`deny`)
                                    enforcement-only vocabulary (Decision 7).
                                    Not the kernel authorization outcome
                                    (`OperationAwareDecisionOutcome`, three
                                    values).
  OperationAwareEnforcementResult  Immutable carrier binding one evaluation's
                                    `OperationAwareDecisionResponse`, optional
                                    `AuditEvidence`, and `EnforcementDisposition`
                                    together (Decision 6).
  OperationAwareEnforcementPoint   Composes `OperationAwareEvaluationEngine`
                                    and the two response/evidence assembly
                                    functions behind a fail-closed `evaluate()`
                                    that never raises (Decisions 2, 5, 8, 9).

What this module does not do
──────────────────────────────
It does not re-evaluate selectors, conditions, or aggregation; does not
recompute or reinterpret any fact `OperationAwareEvaluationEngine.evaluate()`,
`assemble_operation_aware_decision_response()`, or `assemble_audit_evidence()`
already determined; does not load policy; does not write, persist, sign, or
transmit `AuditEvidence`; does not construct `GatewayAuditEvent`; does not
perform HTTP, JWT/OIDC, network, filesystem, or database work; does not
generate a clock value, a UUID, or any random value — every deterministic
fact (`trace_id`, `evidence_id`, `recorded_at`) is caller-supplied (Decision
4). See ADR-0006 for the full boundary this module implements.

Disposition mapping (Decision 7)
──────────────────────────────────
`disposition = allow` only when evaluation completed
(`evaluation_status = completed`) and the authoritative kernel outcome is
`allow`. Every other case — explicit `deny`, default deny, `not_applicable`,
any governed evaluator failure, or an unexpected internal failure — is
`disposition = deny`. The response is never rewritten to agree with the
disposition; `not_applicable` stays `not_applicable`, and a failed
evaluation stays `evaluation_status = failed` / `outcome = null`.

Public API status: internal to `basis_core.enforcement`, not exported from
`basis_core.enforcement.__init__` or `basis_core.__init__`. Public export is
Milestone 11, PR 35's decision (ADR-0006 Decision 14).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from basis_core.audit.operation_aware.audit_evidence import AuditEvidence
from basis_core.decisions.operation_aware import (
    OperationAwareDecisionOutcome,
    OperationAwareDecisionRequest,
    OperationAwareEvaluationStatus,
    OperationAwareFailureReason,
)
from basis_core.evaluation.operation_aware.engine import OperationAwareEvaluationEngine
from basis_core.evaluation.operation_aware.response import OperationAwareDecisionResponse
from basis_core.evaluation.operation_aware.response_assembly import (
    assemble_audit_evidence,
    assemble_operation_aware_decision_response,
)
from basis_core.policy.operation_aware.bundle import PolicyBundle

__all__ = [
    "EnforcementDisposition",
    "OperationAwareEnforcementPoint",
    "OperationAwareEnforcementResult",
]


class EnforcementDisposition(str, Enum):
    """
    Closed, two-value enforcement-only vocabulary — the enforcement point's
    own safe caller-facing action. Distinct from `OperationAwareDecisionOutcome`
    (three values: `allow`/`deny`/`not_applicable`), a rule effect, an
    evaluation status, a gateway execution result, and proof that any
    downstream protocol command actually executed. See ADR-0006 Decision 7.
    """

    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True, slots=True)
class OperationAwareEnforcementResult:
    """
    Immutable, enforcement-owned carrier binding one evaluation's three
    artifacts together (ADR-0006 Decision 6): the authoritative
    `OperationAwareDecisionResponse`, the produced-but-never-written
    `AuditEvidence` (absent only when it could not be trustworthily
    assembled — Decision 9), and this enforcement point's own
    `EnforcementDisposition`.

    Not a published `basis-schemas` contract, not a subclass of
    `OperationAwareDecisionResponse`, and not extended with gateway,
    persistence, or execution-success fields — `frozen=True, slots=True`
    makes both mutation after construction and attaching an undeclared
    field structurally impossible.
    """

    response: OperationAwareDecisionResponse
    audit_evidence: AuditEvidence | None
    disposition: EnforcementDisposition


def _derive_disposition(response: OperationAwareDecisionResponse) -> EnforcementDisposition:
    """
    ADR-0006 Decision 7's disposition mapping, applied to an already-
    assembled `OperationAwareDecisionResponse`. `allow` only when evaluation
    completed and the authoritative outcome is `allow`; `deny` for every
    other reachable or defensively-unreachable state (explicit deny, default
    deny, `not_applicable`, or any failed evaluation).
    """
    if (
        response.evaluation_status is OperationAwareEvaluationStatus.COMPLETED
        and response.outcome is OperationAwareDecisionOutcome.ALLOW
    ):
        return EnforcementDisposition.ALLOW
    return EnforcementDisposition.DENY


def _internal_error_result(
    *,
    request: OperationAwareDecisionRequest,
    bundle: PolicyBundle,
    trace_id: str,
) -> OperationAwareEnforcementResult:
    """
    ADR-0006 Decision 9's catastrophic-failure fallback. Independent of
    `assemble_operation_aware_decision_response` (an exception in that
    function must not prevent a safe return) and of `assemble_audit_evidence`
    (no trustworthy completed trace exists to build evidence from — Decision
    9 permits `audit_evidence = None` here).

    Preserves only facts that remain trustworthy without re-running the
    failing computation: `request.request_id`/`request.correlation_id`
    (already validated by `OperationAwareDecisionRequest`'s own construction),
    the caller-supplied `trace_id` as a reference only (never embedded — no
    honest `EvaluationTrace` exists), and the configured bundle's own
    `bundle_id`/`bundle_version` (fixed at this enforcement point's
    construction, never derived from the failing evaluation).
    """
    response = OperationAwareDecisionResponse(
        request_id=request.request_id,
        correlation_id=request.correlation_id,
        evaluation_status=OperationAwareEvaluationStatus.FAILED,
        outcome=None,
        failure_reason=OperationAwareFailureReason.INTERNAL_EVALUATION_ERROR,
        bundle_id=bundle.bundle_id,
        bundle_version=bundle.bundle_version,
        trace_id=trace_id,
        evaluation_trace=None,
        reason_code=None,
        explanation=None,
    )
    return OperationAwareEnforcementResult(
        response=response,
        audit_evidence=None,
        disposition=EnforcementDisposition.DENY,
    )


class OperationAwareEnforcementPoint:
    """
    The operation-aware enforcement boundary (ADR-0006). A new, separate
    sibling of `basis_core.enforcement.enforcement.EnforcementPoint` — not a
    subclass, and not a shared-implementation variant (Decision 1).

    Configured, at construction, with exactly the two dependencies ADR-0006
    Decision 2 fixes: an `OperationAwareEvaluationEngine` and an
    already-constructed, already-validated `PolicyBundle`. This enforcement
    point does not load policy from a file, environment variable, database,
    or network source, and holds no `AuditWriter` — the operation-aware
    surface never writes `AuditEvidence` (Decision 11).
    """

    def __init__(
        self,
        engine: OperationAwareEvaluationEngine,
        bundle: PolicyBundle,
    ) -> None:
        self._engine = engine
        self._bundle = bundle

    def evaluate(
        self,
        *,
        request: OperationAwareDecisionRequest,
        trace_id: str,
        evidence_id: str,
        recorded_at: datetime,
        embed_evaluation_trace: bool = False,
    ) -> OperationAwareEnforcementResult:
        """
        Evaluate `request` against this enforcement point's configured
        bundle and return an `OperationAwareEnforcementResult`. Never
        raises (ADR-0006 Decision 9).

        Normal flow (Decision 5): `OperationAwareEvaluationEngine.evaluate()`
        produces an `EvaluationTrace`; `assemble_operation_aware_decision_
        response()` and `assemble_audit_evidence()` each compose it,
        unchanged, into the two published kernel artifacts; this method
        derives `disposition` from the assembled response only (Decision 7)
        and returns all three together. This method re-evaluates nothing —
        every applicability, selector, condition, and aggregation fact is
        already authoritative by the time it reaches this method.

        A governed evaluator failure (Decision 8 — any of the six
        `OperationAwareFailureReason` categories reachable through the
        engine) is not an escaped exception: the corresponding failed
        response and its valid `AuditEvidence` are assembled and returned
        normally, with `disposition = deny`.

        An unexpected exception anywhere in this composition (engine
        invocation, response assembly, audit-evidence assembly, or
        disposition derivation) is caught here and converted into a fixed,
        internal-error result via `_internal_error_result` (Decision 9) —
        never re-raised, never exposing exception text, a class name, or a
        stack trace to the caller.

        Args:
            request: an already-constructed, already-validated
                `OperationAwareDecisionRequest`. Not mutated.
            trace_id: caller-supplied; forwarded to the engine unchanged and
                never generated here.
            evidence_id: caller-supplied; forwarded to `assemble_audit_
                evidence` unchanged and never generated here.
            recorded_at: caller-supplied, timezone-aware timestamp;
                forwarded to `assemble_audit_evidence` unchanged and never
                derived from a clock here.
            embed_evaluation_trace: `True` to embed the full `EvaluationTrace`
                on the returned response; `False` (the default) for a
                reference-only response (`response.trace_id` set,
                `response.evaluation_trace` absent) — matching the vendored
                canonical compatibility fixtures' own reference-only shape.
                Never inferred; always this explicit caller choice.

        Returns:
            An `OperationAwareEnforcementResult`. Never raises.
        """
        try:
            trace = self._engine.evaluate(
                request=request,
                bundle=self._bundle,
                trace_id=trace_id,
            )
            response = assemble_operation_aware_decision_response(
                trace=trace,
                embed_evaluation_trace=embed_evaluation_trace,
            )
            audit_evidence = assemble_audit_evidence(
                request=request,
                trace=trace,
                evidence_id=evidence_id,
                recorded_at=recorded_at,
            )
            disposition = _derive_disposition(response)
            return OperationAwareEnforcementResult(
                response=response,
                audit_evidence=audit_evidence,
                disposition=disposition,
            )
        except Exception:
            return _internal_error_result(
                request=request,
                bundle=self._bundle,
                trace_id=trace_id,
            )
