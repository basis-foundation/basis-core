"""
basis_core.audit.operation_aware.evaluation_trace — the `EvaluationTrace`
data model.

`EvaluationTrace` is the bounded, deterministic explanation of one kernel
authorization evaluation, published by `basis-schemas`' `evaluation-trace`
contract (ADR-0003 §4, §13). It is separate from v0.1's
`basis_core.audit.trace.DecisionTrace` (no subclassing, no shared fields)
and is not `AuditEvidence` or `GatewayAuditEvent` — those are later,
separately-scoped surfaces. This module performs no evaluation, no trace
assembly, no conversion from any evaluator result, no ID generation, and no
clock or random access; it only validates an already-produced trace.

Required-nullable fields
────────────────────────
`outcome` and `bundle_applicability` are required keys whose value may be
`null` — the caller must always supply the key, but the value itself may be
`None`. This is distinct from this model's other nullable fields
(`correlation_id`, `bundle_id`, `bundle_version`, `failure_reason`,
`reason_code`, `explanation`), which are optional and default to `None`
when omitted.

Vocabulary ownership
────────────────────
`EvaluationStatus`, `TraceOutcome`, `TraceBundleApplicability`, and
`TraceFailureReason` are defined locally in this module rather than
imported, because `audit/` may import only `domain/`
(`docs/import-boundaries.md`). `TraceBundleApplicability` is therefore
parity-tested against, but never imported from,
`policy.operation_aware.applicability.ApplicabilityResult`; `TraceOutcome`
and `TraceFailureReason` are distinct from their differently-shaped v0.1
counterparts on `basis_core.audit.trace`.

Published cross-field invariants (see `evaluation-trace.yaml`'s
`constraints` block):

  1. `outcome` is null if and only if `evaluation_status` is `failed`.
  2. `failure_reason` is non-null if and only if `evaluation_status` is
     `failed`.
  3. Any `rule_evidence` entry with `rule_result: error` forces
     `evaluation_status` to `failed`.
  4. While `evaluation_status` is `completed`, `outcome` and
     `bundle_applicability` must agree (not required while `failed`).
  5. `bundle_applicability: not_applicable` requires empty `rule_evidence`.
  6. `rule_id` values within `rule_evidence` must be unique.

Ordering
────────
`rule_evidence` preserves caller-supplied order exactly; this model never
sorts or deduplicates it. Array position is never authorization precedence
(`evaluation-trace.yaml`'s own `trace_ordering` block).

Required-nullable serialization
────────────────────────────────
Pydantic's `exclude_none=True` drops any `None`-valued key regardless of
whether the field is required or optional. That's safe for this model's
optional fields, but not for `outcome`/`bundle_applicability`: dropping
them would produce a document missing a required key and would make
"evaluation failed" indistinguishable from "field omitted." A
`@model_serializer(mode="wrap")` restores those two keys, as explicit
`null`, whenever `exclude_none` alone caused their omission — never when
the caller's own `include`/`exclude` selection excluded them, and never for
any other field. Unlike overriding `model_dump`, a `model_serializer`
participates in Pydantic's core serialization schema, so it applies
uniformly whether this model is serialized directly (`model_dump`,
`model_dump_json`) or nested inside a parent model (a parent's
`model_dump`/`model_dump_json`, at any depth).

Public API status: internal to the operation-aware package, not
re-exported from `basis_core.audit` or any package `__init__.py`. Field
reassignment is blocked by `frozen=True`; this does not deeply freeze
`rule_evidence`'s underlying list object.
"""

from __future__ import annotations

import re
from enum import Enum
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

from basis_core.audit.operation_aware.trace_rule_evidence import RuleResult, TraceRuleEvidence
from basis_core.domain.operation_aware_vocabulary import ReasonCode

__all__ = [
    "EvaluationStatus",
    "EvaluationTrace",
    "TraceBundleApplicability",
    "TraceFailureReason",
    "TraceOutcome",
]


def _require_non_empty(value: str, *, field_name: str) -> str:
    """Shared non-empty/non-whitespace-only check for required string
    fields (`trace_id`, `request_id`)."""
    if not value.strip():
        raise ValueError(f"EvaluationTrace.{field_name} must not be empty or whitespace-only.")
    return value


def _require_non_empty_if_present(value: str | None, *, field_name: str) -> str | None:
    """Shared non-empty check for optional string fields that must be
    non-empty *when present* (`bundle_id`, `explanation`)."""
    if value is not None and not value.strip():
        raise ValueError(
            f"EvaluationTrace.{field_name} must not be empty or whitespace-only when provided."
        )
    return value


# Reproduced locally rather than imported — this repository's convention for
# simple, stable patterns is to duplicate them per module rather than share a
# compiled copy across packages that must not import from one another.
_BUNDLE_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")


# `reason_code` reuses `ReasonCode` (domain-layer) structurally via a small
# `PlainValidator`/`PlainSerializer` wrapper. An identical wrapper already
# exists in this package's sibling module, `trace_rule_evidence.py` (PR 24);
# reproduced here rather than imported to keep this file's reason-code
# integration self-contained. This third copy is acknowledged
# package-internal debt (audit/operation_aware/ has no import-boundary
# reason to duplicate it a second time within itself) — left unconsolidated
# in this PR; a future package-internal cleanup may unify it.


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


# ══════════════════════════════════════════════════════════════════════════
# Closed vocabularies — local to this module (see module docstring,
# "Vocabulary ownership")
# ══════════════════════════════════════════════════════════════════════════


class EvaluationStatus(str, Enum):
    """Closed vocabulary: whether evaluation completed (`completed`) or
    could not (`failed`). Not an authorization outcome — see `TraceOutcome`.
    """

    COMPLETED = "completed"
    FAILED = "failed"


class TraceOutcome(str, Enum):
    """Closed authorization-outcome vocabulary, matching
    `decision-response`/`policy-rule`'s outcome vocabulary exactly.
    Required-nullable on `EvaluationTrace.outcome` — see the module
    docstring."""

    ALLOW = "allow"
    DENY = "deny"
    NOT_APPLICABLE = "not_applicable"


class TraceBundleApplicability(str, Enum):
    """Closed bundle-applicability vocabulary. Stores an already-determined
    classification only — this model performs no applicability
    determination; see the module docstring, "Vocabulary ownership"."""

    APPLICABLE = "applicable"
    NOT_APPLICABLE = "not_applicable"


class TraceFailureReason(str, Enum):
    """Closed, six-value evaluator-failure vocabulary (ADR-0002 §14).
    Distinct from the open `reason_code` field and from v0.1's differently-
    shaped, four-value `failure_reason`."""

    INVALID_REQUEST = "invalid_request"
    UNSUPPORTED_SCHEMA_VERSION = "unsupported_schema_version"
    INVALID_POLICY_BUNDLE = "invalid_policy_bundle"
    POLICY_VALIDATION_FAILURE = "policy_validation_failure"
    CONDITION_EVALUATION_ERROR = "condition_evaluation_error"
    INTERNAL_EVALUATION_ERROR = "internal_evaluation_error"


# ══════════════════════════════════════════════════════════════════════════
# EvaluationTrace
# ══════════════════════════════════════════════════════════════════════════

#: Fields that are *required keys* on every `EvaluationTrace` but whose
#: *value* may be `null` — see the module docstring's "Required-nullable
#: fields" and "Required-nullable serialization" sections. Every other
#: nullable field on this model is optional (defaults to `None` when
#: absent), and is deliberately left to Pydantic's normal `exclude_none`
#: behavior by the serializer below.
_REQUIRED_NULLABLE_FIELDS: tuple[str, ...] = ("outcome", "bundle_applicability")


class EvaluationTrace(BaseModel):
    """Bounded, deterministic explanation of one kernel authorization
    evaluation — see the module docstring for field shape, required-
    nullable behavior, vocabulary ownership, invariants, and serialization.
    """

    trace_id: str
    request_id: str
    correlation_id: str | None = None
    evaluation_status: EvaluationStatus
    outcome: TraceOutcome | None
    bundle_applicability: TraceBundleApplicability | None
    bundle_id: str | None = None
    bundle_version: str | None = None
    failure_reason: TraceFailureReason | None = None
    rule_evidence: list[TraceRuleEvidence]
    reason_code: ReasonCodeField = None
    explanation: str | None = None

    model_config = ConfigDict(frozen=True, extra="forbid")

    # ── Field-level validation ───────────────────────────────────────────

    @field_validator("trace_id", mode="after")
    @classmethod
    def _trace_id_must_not_be_empty(cls, v: str) -> str:
        return _require_non_empty(v, field_name="trace_id")

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
                f"EvaluationTrace.bundle_version {v!r} does not match the required "
                r"semver pattern '^\d+\.\d+\.\d+$'."
            )
        return v

    @field_validator("explanation", mode="after")
    @classmethod
    def _explanation_must_not_be_empty_if_present(cls, v: str | None) -> str | None:
        return _require_non_empty_if_present(v, field_name="explanation")

    # ── Cross-field invariants ───────────────────────────────────────────
    # Each enforces the identically-numbered invariant in the module
    # docstring's list, cited against the vendored `evaluation-trace.yaml`
    # `constraints` block.

    @model_validator(mode="after")
    def _check_outcome_null_iff_failed(self) -> EvaluationTrace:
        """Invariant 1."""
        if self.evaluation_status is EvaluationStatus.FAILED and self.outcome is not None:
            raise ValueError(
                "EvaluationTrace.outcome must be null when evaluation_status is 'failed'; "
                "a failed evaluation must never serialize a non-null outcome."
            )
        if self.evaluation_status is EvaluationStatus.COMPLETED and self.outcome is None:
            raise ValueError(
                "EvaluationTrace.outcome must be one of 'allow', 'deny', or 'not_applicable' "
                "when evaluation_status is 'completed'."
            )
        return self

    @model_validator(mode="after")
    def _check_failure_reason_null_iff_failed(self) -> EvaluationTrace:
        """Invariant 2."""
        if self.evaluation_status is EvaluationStatus.FAILED and self.failure_reason is None:
            raise ValueError(
                "EvaluationTrace.failure_reason must be non-null when evaluation_status is "
                "'failed'."
            )
        if self.evaluation_status is EvaluationStatus.COMPLETED and self.failure_reason is not None:
            raise ValueError(
                "EvaluationTrace.failure_reason must be null when evaluation_status is 'completed'."
            )
        return self

    @model_validator(mode="after")
    def _check_rule_error_forces_failed_status(self) -> EvaluationTrace:
        """Invariant 3."""
        if self.evaluation_status is not EvaluationStatus.FAILED:
            if any(entry.rule_result is RuleResult.ERROR for entry in self.rule_evidence):
                raise ValueError(
                    "EvaluationTrace.evaluation_status must be 'failed' when any "
                    "rule_evidence entry has rule_result 'error'; a rule-evaluation error "
                    "can never coexist with a completed allow or deny outcome."
                )
        return self

    @model_validator(mode="after")
    def _check_completed_outcome_bundle_applicability_agreement(self) -> EvaluationTrace:
        """Invariant 4."""
        if self.evaluation_status is not EvaluationStatus.COMPLETED:
            return self
        if self.outcome is None:
            # Invariant 1 already rejects this combination.
            return self
        if self.outcome is TraceOutcome.NOT_APPLICABLE:
            if self.bundle_applicability is not TraceBundleApplicability.NOT_APPLICABLE:
                raise ValueError(
                    "EvaluationTrace.outcome 'not_applicable' requires bundle_applicability "
                    "'not_applicable' when evaluation_status is 'completed'."
                )
        else:
            if self.bundle_applicability is not TraceBundleApplicability.APPLICABLE:
                raise ValueError(
                    "EvaluationTrace.outcome 'allow'/'deny' requires bundle_applicability "
                    "'applicable' when evaluation_status is 'completed'."
                )
        return self

    @model_validator(mode="after")
    def _check_not_applicable_bundle_requires_empty_rule_evidence(self) -> EvaluationTrace:
        """Invariant 5."""
        if (
            self.bundle_applicability is TraceBundleApplicability.NOT_APPLICABLE
            and len(self.rule_evidence) > 0
        ):
            raise ValueError(
                "EvaluationTrace.rule_evidence must be empty when bundle_applicability is "
                "'not_applicable'; no policy bundle applied, so no rule was ever a candidate."
            )
        return self

    @model_validator(mode="after")
    def _check_rule_evidence_rule_id_uniqueness(self) -> EvaluationTrace:
        """Invariant 6."""
        seen: set[str] = set()
        for entry in self.rule_evidence:
            if entry.rule_id in seen:
                raise ValueError(
                    "EvaluationTrace.rule_evidence contains a duplicate rule_id "
                    f"{entry.rule_id!r}; rule_id values must be unique within one trace's "
                    "rule_evidence array."
                )
            seen.add(entry.rule_id)
        return self

    # ── Serialization ─────────────────────────────────────────────────────

    @model_serializer(mode="wrap")
    def _serialize_with_required_nullable_keys(
        self, handler: SerializerFunctionWrapHandler, info: SerializationInfo
    ) -> Any:
        """Restore `outcome`/`bundle_applicability` (as explicit `null`)
        whenever `exclude_none` alone caused Pydantic's default
        serialization to drop them — see the module docstring, "Required-
        nullable serialization."

        `handler(self)` produces Pydantic's normal result for this model,
        already honoring `mode`, `include`, `exclude`, `by_alias`,
        `exclude_unset`, `exclude_defaults`, `round_trip`, and every other
        `SerializationInfo` setting unchanged — this method touches nothing
        about that result except the two named keys, and only when
        `exclude_none` is the reason either is missing:

          - If `exclude_none` is not set, `handler`'s result is returned
            unmodified.
          - If a key is already present (non-null, or restored by a nested
            call), it is left alone.
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
        `model_dump_json` — unlike a `model_dump` method override, which
        only affects direct top-level calls.
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
