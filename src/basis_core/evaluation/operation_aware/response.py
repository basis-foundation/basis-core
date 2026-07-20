"""
basis_core.evaluation.operation_aware.response — the
`OperationAwareDecisionResponse` data model.

This is the third module added under `src/basis_core/evaluation/
operation_aware/` (see
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`, Milestone 10,
PR 29 — "OperationAwareDecisionResponse model"), after PR 26's
`trace_assembly.py` and PR 27B's `engine.py`. It implements the published
response shape from `basis-schemas` v0.2.1's `operation-aware-decision-
response` contract (ADR-0001 §4; ADR-0002 §4-5,14):

  OperationAwareDecisionResponse   The additive, richer sibling of the
                                    first-wave `decisions.models.
                                    DecisionResponse` — the authoritative
                                    kernel evaluation result for one
                                    `OperationAwareDecisionRequest`.

Module-location correction — the roadmap's stale placement
────────────────────────────────────────────────────────────────────────────
`docs/implementation/basis-core-v0.2-operation-aware-plan.md` Section 3's
mapping table (and Section 5's original module-tree sketch) proposed
`OperationAwareDecisionResponse` as a `decisions/operation_aware.py` symbol.
That placement predates `basis-architecture` ADR-0006 ("Introduce a Pure
Evaluation Orchestration Layer"), which Section 5's own "Supersession note"
already applied to `trace_assembly.py`, `engine.py`, and
`response_assembly.py` — moving them from a `policy/operation_aware/`
sketch to `evaluation/operation_aware/` — but never went back and corrected
the Section 3 table row for this response model specifically. This module
corrects that same gap for `OperationAwareDecisionResponse`: the response
type embeds `EvaluationTrace` (audit-owned; `docs/import-boundaries.md`
permits `audit/` to import only `domain/` and `decisions/`), and
`decisions/` must never import `audit/` (no such edge exists anywhere in
the permission matrix). Placing the *complete* response model in
`decisions/operation_aware.py` would therefore require an illegal
`decisions → audit` import merely to type the embedded `evaluation_trace`
field. `docs/kernel-constitution.md`'s own description of the evaluation
layer is explicit that this is exactly its job: "[`evaluation/`] ... invokes
policy-owned semantic operations and composes their typed results into
bounded decision, trace, response, and kernel audit-evidence artifacts."
This module therefore lives at `evaluation/operation_aware/response.py`,
following `trace_assembly.py`/`engine.py`'s precedent, not the stale
roadmap table entry. See this PR's final report for the explicit
architectural-conflict disclosure this correction required.

Shared vocabulary reuse — no new response-only vocabulary invented
────────────────────────────────────────────────────────────────────────────
`evaluation_status` and `outcome` reuse two new decisions-owned enums added
by this same PR, `OperationAwareEvaluationStatus` and
`OperationAwareDecisionOutcome` (`basis_core.decisions.operation_aware`),
value- and member-name-parity-tested against the audit-owned
`EvaluationStatus`/`TraceOutcome` this module also imports (for the
embedded trace) — see that module's docstring for the "lowest common legal
dependency" ownership reasoning, which mirrors `OperationAwareFailureReason`
exactly. `failure_reason` reuses `OperationAwareFailureReason`
(`decisions/operation_aware.py`, added by PR 27A) directly — no third
failure-reason vocabulary is added by this PR. `reason_code` reuses
`domain.operation_aware_vocabulary.ReasonCode` unchanged, via the same
small `PlainValidator`/`PlainSerializer` wrapper this package's sibling
modules (`trace_rule_evidence.py`, `evaluation_trace.py`) already use —
reproduced locally here for the same "audit/policy cannot share a private
wrapper" reason those modules' docstrings give, adapted to this module's own
legal import set.

Scope — model definition and contract validation only
────────────────────────────────────────────────────────────────────────────
This module implements construction-time structural and cross-field
validation only. It does not implement, and must not be extended in this PR
to implement:
  - response assembly from an `EvaluationTrace` or an
    `OperationAwareEvaluationEngine` result (`response_assembly.py` is
    later, separately-scoped roadmap work — PR 31);
  - `AuditEvidence` (Milestone 10, PR 30 — a separate model, separately
    scoped);
  - full response/trace/audit-evidence agreement enforcement beyond the
    narrow subset described below (PR 32);
  - enforcement behavior, gateway behavior, or any I/O;
  - public API stabilization (Milestone 11, PR 35) — this module is not
    re-exported from `basis_core.evaluation`, `basis_core`, or any package
    `__init__.py`.

Response/trace agreement — narrow, fixture-driven subset only, not the
full PR 32 boundary
────────────────────────────────────────────────────────────────────────────
The vendored contract's `constraints` block (see
`tests/fixtures/basis-schemas/v0.2.1/schemas/operation-aware-decision-
response/operation-aware-decision-response.yaml`) documents, in prose, a
broad response/embedded-trace agreement requirement: when `evaluation_trace`
is present, its `request_id`, `evaluation_status`, `outcome`,
`failure_reason`, `correlation_id` (when both present), `bundle_id`/
`bundle_version` (when both carry them), and `reason_code` (when both
non-null) must all agree with this response's own fields, and — when both
`trace_id` and `evaluation_trace` are present — `evaluation_trace.trace_id`
must equal `trace_id`. The same prose explicitly says this agreement is
"documented here, checked by tests, expected of a future runtime, not by
YAML-level cross-field validation alone" — i.e. the contract does not
require every model in the ecosystem to enforce every clause; validation is
expected to be phased in across the roadmap's own PRs (this repository's
Milestone 10 vs. Milestone 10's separately-numbered PR 32 for full
response/trace/audit-evidence agreement).

This PR's brief is explicit that full cross-artifact agreement enforcement
is out of scope here and remains PR 32's responsibility. This module
therefore enforces only the narrow subset of that prose invariant that the
vendored contract's own `examples.invalid` fixtures actually exercise as
rejection cases:

  - `request_id` — `evaluation_trace.request_id` must equal this response's
    own `request_id` when `evaluation_trace` is present. Exercised by the
    "response/trace request-ID mismatch" invalid example.
  - `correlation_id` — must agree when *both* this response's and the
    embedded trace's `correlation_id` are non-null. Exercised by the
    "response/trace correlation_id mismatch" invalid example.
  - `failure_reason` — `evaluation_trace.failure_reason` must equal this
    response's own `failure_reason` when `evaluation_trace` is present
    (both may be `None`, in which case they trivially agree). Exercised by
    the "response/trace failure_reason mismatch" invalid example.
  - `reason_code` — must agree when *both* this response's and the embedded
    trace's `reason_code` are non-null. Exercised by the "response/trace
    reason_code mismatch (both non-null but disagree)" invalid example.

Deliberately NOT enforced by this PR (left to PR 32, which owns full
response/trace/audit-evidence agreement, per this PR's brief):
`evaluation_status` agreement, `outcome` agreement, `bundle_id`/
`bundle_version` agreement, and `trace_id`-vs-`evaluation_trace.trace_id`
agreement. None of the vendored `examples.invalid` fixtures exercise any of
these four as a rejection case, and implementing all of the prose's
agreement clauses now — rather than only the four the fixtures actually
require — would silently absorb the entirety of PR 32's scope into this PR.
This is a genuine, disclosed overlap with the future PR 32 boundary, not an
oversight: see this PR's final report, "Whether response/trace agreement is
enforced or deferred, and why," for the explicit disclosure the brief
requires.

`evaluation_trace`'s own internal structural validity (e.g. a missing
`trace_id`) is already, and independently, enforced by `EvaluationTrace`'s
own construction-time validation (PR 25) — this module performs no
duplicate structural checking of the embedded trace, does not mutate it,
and does not derive any of this response's own fields from it.

Evaluation-state invariants (this response's own fields)
────────────────────────────────────────────────────────────────────────────
Mirrors `EvaluationTrace`'s own `outcome`/`failure_reason` invariants
exactly (ADR-0002 §14), applied to this response's own top-level fields:

  1. `outcome` is null if and only if `evaluation_status` is `failed`.
  2. `failure_reason` is non-null if and only if `evaluation_status` is
     `failed`.

A failed evaluation can therefore never serialize a non-null `outcome` —
evaluation failure is never silently normalized into a substantive `deny`.
This module supplies no default `outcome` or `failure_reason`; both must be
supplied explicitly by the caller (response assembly, PR 31) for every
construction.

Required-nullable serialization
────────────────────────────────────────────────────────────────────────────
`outcome` and `failure_reason` are required keys whose value may be `None`
— the same required-nullable shape `EvaluationTrace.outcome`/
`bundle_applicability` already has (PR 25). Pydantic's `exclude_none=True`
drops any `None`-valued key regardless of whether the field is required, so
a plain `model_dump(exclude_none=True)` would make "evaluation failed"
(both null) indistinguishable from "field omitted." This module follows
`EvaluationTrace`'s own proven `@model_serializer(mode="wrap")` pattern
(not a `model_dump` override, which would neither fire for
`model_dump_json` nor for this model nested inside a parent model's own
`model_dump`/`model_dump_json`) to restore `outcome`/`failure_reason` as
explicit `null` whenever `exclude_none` alone caused their omission — never
when the caller's own `include`/`exclude` selection excluded them.

Import boundary
────────────────────────────────────────────────────────────────────────────
This module imports from `basis_core.audit.operation_aware.
evaluation_trace` (for `EvaluationTrace`), `basis_core.decisions.
operation_aware` (for the shared vocabularies above), and
`basis_core.domain.operation_aware_vocabulary` (for `ReasonCode`) — all
legal per `docs/import-boundaries.md` (`evaluation/` may import `domain/`,
`decisions/`, `policy/`, `audit/`). It does not import
`basis_core.adapters`, `basis_core.enforcement`, or `basis_core.policy` (no
policy-owned type is needed to define this response's shape). The existing
recursive guard, `tests/test_import_boundaries.py::
test_evaluation_operation_aware_does_not_import_from_adapters_or_enforcement`,
already covers this module (it scans `evaluation/operation_aware/`
recursively) — no new boundary test is added for this PR.

Public API status: internal to the operation-aware package, exactly like
every other operation-aware module added so far. Not re-exported from
`basis_core.evaluation`, `basis_core`, or any other package `__init__.py`.
"""

from __future__ import annotations

import re
from typing import Annotated, Any

from pydantic import (
    BaseModel,
    ConfigDict,
    PlainSerializer,
    PlainValidator,
    SerializationInfo,
    SerializerFunctionWrapHandler,
    field_validator,
    model_serializer,
    model_validator,
)

from basis_core.audit.operation_aware.evaluation_trace import EvaluationTrace
from basis_core.decisions.operation_aware import (
    OperationAwareDecisionOutcome,
    OperationAwareEvaluationStatus,
    OperationAwareFailureReason,
)
from basis_core.domain.operation_aware_vocabulary import ReasonCode

__all__ = ["OperationAwareDecisionResponse"]


def _require_non_empty(value: str, *, field_name: str) -> str:
    """Shared non-empty/non-whitespace-only check for required string
    fields (`request_id`)."""
    if not value.strip():
        raise ValueError(
            f"OperationAwareDecisionResponse.{field_name} must not be empty or whitespace-only."
        )
    return value


def _require_non_empty_if_present(value: str | None, *, field_name: str) -> str | None:
    """Shared non-empty check for optional string fields that must be
    non-empty *when present* (`bundle_id`, `trace_id`, `explanation`)."""
    if value is not None and not value.strip():
        raise ValueError(
            f"OperationAwareDecisionResponse.{field_name} must not be empty or "
            "whitespace-only when provided."
        )
    return value


# Reproduced locally rather than imported — this repository's convention for
# simple, stable patterns is to duplicate them per module rather than share a
# compiled copy across packages that must not import from one another (see
# `EvaluationTrace`'s own `_BUNDLE_VERSION_RE`, reproduced identically here).
_BUNDLE_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")


# `reason_code` reuses `ReasonCode` (domain-layer) structurally via a small
# `PlainValidator`/`PlainSerializer` wrapper. Identical wrappers already
# exist in this package's sibling modules (`audit/operation_aware/
# trace_rule_evidence.py`, `audit/operation_aware/evaluation_trace.py`) and
# in `policy/operation_aware/rule.py`; reproduced here rather than imported
# to keep this module's reason-code integration self-contained, matching
# those modules' own stated reasoning (`evaluation/` could legally import
# `audit/`'s copy, but this module does not require or assume that either
# sibling module exposes its wrapper for reuse).


def _construct_reason_code(value: object) -> ReasonCode | None:
    if value is None:
        return None
    if isinstance(value, ReasonCode):
        return value
    if isinstance(value, str):
        return ReasonCode(value)
    raise TypeError(f"reason_code must be a string or None, got {type(value).__name__}.")


ReasonCodeField = Annotated[
    ReasonCode | None,
    PlainValidator(_construct_reason_code),
    PlainSerializer(lambda v: str(v) if v is not None else None, return_type=str | None),
]


#: Fields that are *required keys* on every `OperationAwareDecisionResponse`
#: but whose *value* may be `null` — see the module docstring's
#: "Required-nullable serialization." Every other nullable field on this
#: model is optional (defaults to `None` when absent) and is left to
#: Pydantic's normal `exclude_none` behavior by the serializer below.
_REQUIRED_NULLABLE_FIELDS: tuple[str, ...] = ("outcome", "failure_reason")


class OperationAwareDecisionResponse(BaseModel):
    """
    The operation-aware authorization response — an additive, richer sibling
    of `decisions.models.DecisionResponse` carrying the authoritative kernel
    evaluation result for one `OperationAwareDecisionRequest`.

    See the module docstring for field shape, required-nullable behavior,
    shared vocabulary ownership, the evaluation-state invariant, the
    narrowly-scoped response/trace agreement checks this PR enforces (and
    the broader agreement clauses it deliberately defers to PR 32), and
    serialization.

    Required fields
    ────────────────
    request_id          Echoes the request_id of the operation-aware-
                        decision-request this response answers. Non-empty.
    evaluation_status   `OperationAwareEvaluationStatus.COMPLETED` or
                        `.FAILED`.
    outcome             `OperationAwareDecisionOutcome` or `None`.
                        Required-nullable: the key is always present; the
                        value is `None` if and only if `evaluation_status`
                        is `failed`.
    failure_reason       `OperationAwareFailureReason` or `None`.
                        Required-nullable: non-`None` if and only if
                        `evaluation_status` is `failed`.

    Optional fields
    ────────────────
    correlation_id       Passed through verbatim; no format constraint
                        beyond string-or-`None`.
    bundle_id            The bundle_id of the policy bundle actually
                        evaluated, when one applied. Non-empty when
                        present.
    bundle_version       The bundle_version of the policy bundle actually
                        evaluated. Semver-shaped when present.
    trace_id             The trace_id of the `EvaluationTrace` that
                        explains this response, when the producer
                        references it by identifier. Non-empty when
                        present. Never generated by this module.
    evaluation_trace      The full `EvaluationTrace` explanation, embedded
                        inline, when the producer chooses to embed it.
                        Never derived, mutated, or generated by this
                        module — see the module docstring for the exact,
                        narrow subset of response/trace agreement this
                        model enforces.
    reason_code           Optional `ReasonCode`, reused unchanged.
    explanation           Optional, non-empty-when-present static
                        explanation string.
    """

    request_id: str
    correlation_id: str | None = None
    evaluation_status: OperationAwareEvaluationStatus
    outcome: OperationAwareDecisionOutcome | None
    failure_reason: OperationAwareFailureReason | None
    bundle_id: str | None = None
    bundle_version: str | None = None
    trace_id: str | None = None
    evaluation_trace: EvaluationTrace | None = None
    reason_code: ReasonCodeField = None
    explanation: str | None = None

    model_config = ConfigDict(frozen=True, extra="forbid")

    # ── Field-level validation ───────────────────────────────────────────

    @field_validator("request_id", mode="after")
    @classmethod
    def _request_id_must_not_be_empty(cls, v: str) -> str:
        return _require_non_empty(v, field_name="request_id")

    @field_validator("bundle_id", mode="after")
    @classmethod
    def _bundle_id_must_not_be_empty_if_present(cls, v: str | None) -> str | None:
        return _require_non_empty_if_present(v, field_name="bundle_id")

    @field_validator("bundle_version", mode="after")
    @classmethod
    def _bundle_version_must_match_semver_if_present(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if not _BUNDLE_VERSION_RE.match(v):
            raise ValueError(
                f"OperationAwareDecisionResponse.bundle_version {v!r} does not match "
                r"the required semver pattern '^\d+\.\d+\.\d+$'."
            )
        return v

    @field_validator("trace_id", mode="after")
    @classmethod
    def _trace_id_must_not_be_empty_if_present(cls, v: str | None) -> str | None:
        return _require_non_empty_if_present(v, field_name="trace_id")

    @field_validator("explanation", mode="after")
    @classmethod
    def _explanation_must_not_be_empty_if_present(cls, v: str | None) -> str | None:
        return _require_non_empty_if_present(v, field_name="explanation")

    # ── Cross-field invariants: this response's own evaluation state ─────

    @model_validator(mode="after")
    def _check_outcome_null_iff_failed(self) -> OperationAwareDecisionResponse:
        """Invariant 1 — see the module docstring."""
        if (
            self.evaluation_status is OperationAwareEvaluationStatus.FAILED
            and self.outcome is not None
        ):
            raise ValueError(
                "OperationAwareDecisionResponse.outcome must be null when "
                "evaluation_status is 'failed'; a failed evaluation must never "
                "serialize a non-null outcome."
            )
        if (
            self.evaluation_status is OperationAwareEvaluationStatus.COMPLETED
            and self.outcome is None
        ):
            raise ValueError(
                "OperationAwareDecisionResponse.outcome must be one of 'allow', 'deny', "
                "or 'not_applicable' when evaluation_status is 'completed'."
            )
        return self

    @model_validator(mode="after")
    def _check_failure_reason_null_iff_failed(self) -> OperationAwareDecisionResponse:
        """Invariant 2 — see the module docstring."""
        if (
            self.evaluation_status is OperationAwareEvaluationStatus.FAILED
            and self.failure_reason is None
        ):
            raise ValueError(
                "OperationAwareDecisionResponse.failure_reason must be non-null when "
                "evaluation_status is 'failed'."
            )
        if (
            self.evaluation_status is OperationAwareEvaluationStatus.COMPLETED
            and self.failure_reason is not None
        ):
            raise ValueError(
                "OperationAwareDecisionResponse.failure_reason must be null when "
                "evaluation_status is 'completed'."
            )
        return self

    # ── Cross-field invariants: narrow response/trace agreement subset ───
    # See the module docstring, "Response/trace agreement," for exactly
    # which four clauses this PR enforces and why the rest are deferred to
    # PR 32.

    @model_validator(mode="after")
    def _check_trace_agreement_subset(self) -> OperationAwareDecisionResponse:
        trace = self.evaluation_trace
        if trace is None:
            return self

        if trace.request_id != self.request_id:
            raise ValueError(
                "OperationAwareDecisionResponse.evaluation_trace.request_id "
                f"{trace.request_id!r} does not match this response's own request_id "
                f"{self.request_id!r}."
            )

        if (
            self.correlation_id is not None
            and trace.correlation_id is not None
            and trace.correlation_id != self.correlation_id
        ):
            raise ValueError(
                "OperationAwareDecisionResponse.evaluation_trace.correlation_id "
                f"{trace.correlation_id!r} does not match this response's own "
                f"correlation_id {self.correlation_id!r}."
            )

        trace_failure_reason_value = (
            trace.failure_reason.value if trace.failure_reason is not None else None
        )
        response_failure_reason_value = (
            self.failure_reason.value if self.failure_reason is not None else None
        )
        if trace_failure_reason_value != response_failure_reason_value:
            raise ValueError(
                "OperationAwareDecisionResponse.evaluation_trace.failure_reason "
                f"{trace.failure_reason!r} does not match this response's own "
                f"failure_reason {self.failure_reason!r}."
            )

        if (
            self.reason_code is not None
            and trace.reason_code is not None
            and trace.reason_code != self.reason_code
        ):
            raise ValueError(
                "OperationAwareDecisionResponse.evaluation_trace.reason_code "
                f"{trace.reason_code!r} does not match this response's own reason_code "
                f"{self.reason_code!r}."
            )

        return self

    # ── Serialization ─────────────────────────────────────────────────────

    @model_serializer(mode="wrap")
    def _serialize_with_required_nullable_keys(
        self, handler: SerializerFunctionWrapHandler, info: SerializationInfo
    ) -> Any:
        """Restore `outcome`/`failure_reason` (as explicit `null`) whenever
        `exclude_none` alone caused Pydantic's default serialization to drop
        them — see the module docstring, "Required-nullable serialization,"
        and `EvaluationTrace._serialize_with_required_nullable_keys`, whose
        pattern this mirrors exactly.

        `handler(self)` produces Pydantic's normal result for this model,
        already honoring `mode`, `include`, `exclude`, `by_alias`,
        `exclude_unset`, `exclude_defaults`, `round_trip`, and every other
        `SerializationInfo` setting unchanged, including recursively
        serializing the embedded `evaluation_trace` field through its own
        `@model_serializer` — this method touches nothing about that result
        except the two named top-level keys, and only when `exclude_none` is
        the reason either is missing:

          - If `exclude_none` is not set, `handler`'s result is returned
            unmodified.
          - If a key is already present (non-null), it is left alone.
          - If the caller's own `include` does not select the key, or the
            caller's own `exclude` names it, it is left absent — explicit
            caller intent always wins over restoration.
          - Otherwise (the key is required-nullable, currently `None`, and
            was not filtered out by `include`/`exclude`), it is added back
            as `null`.

        Because this is a `model_serializer`, not an override of
        `model_dump`, it participates in Pydantic's core serialization
        schema and therefore also fires for `model_dump_json` and for this
        model nested at any depth inside a parent model's own `model_dump`/
        `model_dump_json`.
        """
        data = handler(self)
        if not info.exclude_none or not isinstance(data, dict):
            return data
        for field_name in _REQUIRED_NULLABLE_FIELDS:
            if field_name in data:
                continue
            if info.include is not None and field_name not in info.include:
                continue
            if info.exclude is not None and field_name in info.exclude:
                continue
            data[field_name] = None
        return data
