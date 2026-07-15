"""
basis_core.audit.operation_aware.trace_rule_evidence — the `TraceRuleEvidence`
data model.

Implements the bounded, frozen per-rule trace-evidence shape published by
`basis-schemas`' `trace-rule-evidence` contract (ADR-0003 §5):

  TraceRuleEvidence       Bounded explanation record for one policy rule
                          considered during one evaluation: rule identity,
                          closed effect, closed rule_result, optional
                          bounded condition-level evidence, optional
                          reason code, optional static explanation.
  TraceConditionEvidence  Bounded per-condition entry nested inside
                          `condition_results`.
  TraceRuleEffect         Closed `allow`/`deny` vocabulary.
  RuleResult              Closed `matched`/`not_matched`/`skipped`/`error`
                          vocabulary.
  TraceConditionResult    Closed `matched`/`not_matched`/`error` vocabulary.

Scope
─────
This is bounded trace *evidence*, not a policy rule, not an evaluator, and
not a full evaluation trace. It performs no rule matching, condition
evaluation, or trace assembly, and carries no raw compared value, full
request, full rule, or authored condition definition — only the
already-evaluated result. A consumer needing a rule's authored shape
dereferences the originating policy bundle by `rule_id`.

Import boundary
────────────────
`audit/` may import only from `domain/` (`docs/import-boundaries.md`).
`TraceRuleEffect` and `TraceConditionResult` are therefore defined locally
here rather than imported from `policy.operation_aware`, even though their
values are parity-tested against that layer's own vocabularies. `ReasonCode`
remains domain-owned and is imported directly; only its small Pydantic
integration wrapper (`ReasonCodeField` below) is reproduced locally, since
`audit/` cannot import the equivalent wrapper already defined in `policy/`.

This module is internal to the operation-aware package; it is not
re-exported from `basis_core.audit`.
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated

from pydantic import (
    BaseModel,
    ConfigDict,
    PlainSerializer,
    PlainValidator,
    field_validator,
    model_validator,
)

from basis_core.domain.operation_aware_vocabulary import ReasonCode

__all__ = [
    "RuleResult",
    "TraceConditionEvidence",
    "TraceConditionResult",
    "TraceRuleEffect",
    "TraceRuleEvidence",
]


def _require_non_empty(value: str, *, field_name: str) -> str:
    """Shared non-empty/non-whitespace-only check."""
    if not value.strip():
        raise ValueError(f"{field_name} must not be empty or whitespace-only.")
    return value


# `reason_code`: reuse `ReasonCode` structurally, without requiring
# `arbitrary_types_allowed`. `ReasonCode` itself (domain-layer) is imported
# directly; only this small `PlainValidator`/`PlainSerializer` wrapper is
# reproduced locally (an identical wrapper exists in
# `policy/operation_aware/rule.py` — not imported, since `audit/` may not
# import `policy/`).


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
# Closed vocabularies
# ══════════════════════════════════════════════════════════════════════════


class TraceRuleEffect(str, Enum):
    """
    Closed `allow`/`deny` rule-effect vocabulary, parity-tested against
    `policy-rule`'s own effect vocabulary but defined as a distinct local
    type (see this module's "Import boundary"). `not_applicable` is
    excluded — it is a bundle-applicability outcome, not a rule effect.
    """

    ALLOW = "allow"
    DENY = "deny"


class RuleResult(str, Enum):
    """
    Closed rule-result vocabulary for one rule's contribution to an
    evaluation.

    MATCHED       Match/conditions were satisfied.
    NOT_MATCHED   A candidate rule whose match/conditions were not
                  satisfied.
    SKIPPED       Not evaluated at all (e.g. evaluation short-circuited
                  before reaching it) — a per-rule state, distinct from a
                  bundle-level not-applicable outcome.
    ERROR         Could not be evaluated (e.g. a condition raised an
                  evaluation error).
    """

    MATCHED = "matched"
    NOT_MATCHED = "not_matched"
    SKIPPED = "skipped"
    ERROR = "error"


class TraceConditionResult(str, Enum):
    """
    Closed, three-value per-condition result vocabulary. No `skipped`
    value: `skipped` describes a whole rule (`RuleResult.SKIPPED`), not an
    individual condition.
    """

    MATCHED = "matched"
    NOT_MATCHED = "not_matched"
    ERROR = "error"


# ══════════════════════════════════════════════════════════════════════════
# Condition-level evidence
# ══════════════════════════════════════════════════════════════════════════


class TraceConditionEvidence(BaseModel):
    """
    One bounded per-condition evidence entry nested inside
    `TraceRuleEvidence.condition_results`.

    Required: `condition_id` (non-empty; unique within the containing
    record's `condition_results` array), `result`. Optional: `reason_code`,
    `explanation`. Never carries this condition's `field_path`, `operator`,
    `expected_value`, or the raw request value it was compared against.
    """

    condition_id: str
    result: TraceConditionResult
    reason_code: ReasonCodeField = None
    explanation: str | None = None

    model_config = ConfigDict(frozen=True, extra="forbid")

    @field_validator("condition_id", mode="after")
    @classmethod
    def _condition_id_must_not_be_empty(cls, v: str) -> str:
        return _require_non_empty(v, field_name="TraceConditionEvidence.condition_id")

    @field_validator("explanation", mode="after")
    @classmethod
    def _explanation_must_not_be_empty_if_present(cls, v: str | None) -> str | None:
        if v is None:
            return v
        return _require_non_empty(v, field_name="TraceConditionEvidence.explanation")


# ══════════════════════════════════════════════════════════════════════════
# TraceRuleEvidence
# ══════════════════════════════════════════════════════════════════════════


class TraceRuleEvidence(BaseModel):
    """
    Bounded, frozen Pydantic trace-evidence record for one policy rule
    considered during one operation-aware evaluation. Field reassignment is
    prevented according to the repository's current frozen-model
    convention; this does not make `condition_results`' underlying list
    object itself deeply immutable.

    Required: `rule_id` (non-empty), `effect`, `rule_result`. Optional:
    `condition_results` (bounded, preserves supplied order, non-empty when
    present), `reason_code`, `explanation`.

    Validation: `condition_id` values must be unique within
    `condition_results`; any `condition_results` entry with `result: error`
    forces `rule_result: error` (the inverse is not required — a
    `rule_result: error` record is not required to contain any `error`
    condition entry).

    Serialization follows this repository's governed round-trip
    convention: `model_dump(mode="json", exclude_none=True)`.
    """

    rule_id: str
    effect: TraceRuleEffect
    rule_result: RuleResult
    condition_results: list[TraceConditionEvidence] | None = None
    reason_code: ReasonCodeField = None
    explanation: str | None = None

    model_config = ConfigDict(frozen=True, extra="forbid")

    @field_validator("rule_id", mode="after")
    @classmethod
    def _rule_id_must_not_be_empty(cls, v: str) -> str:
        return _require_non_empty(v, field_name="TraceRuleEvidence.rule_id")

    @field_validator("explanation", mode="after")
    @classmethod
    def _explanation_must_not_be_empty_if_present(cls, v: str | None) -> str | None:
        if v is None:
            return v
        return _require_non_empty(v, field_name="TraceRuleEvidence.explanation")

    @field_validator("condition_results", mode="after")
    @classmethod
    def _reject_explicit_empty_condition_results(
        cls, v: list[TraceConditionEvidence] | None
    ) -> list[TraceConditionEvidence] | None:
        if v is None:
            return v
        if len(v) == 0:
            raise ValueError(
                "TraceRuleEvidence.condition_results must be a non-empty array when "
                "present; an explicitly empty array conveys nothing. Omit the field "
                "(or supply null) to signal 'no condition-level evidence'."
            )
        return v

    @model_validator(mode="after")
    def _check_condition_id_uniqueness(self) -> TraceRuleEvidence:
        seen: set[str] = set()
        for entry in self.condition_results or ():
            if entry.condition_id in seen:
                raise ValueError(
                    "TraceRuleEvidence.condition_results contains a duplicate "
                    f"condition_id {entry.condition_id!r}; condition_id values must be "
                    "unique within one rule-evidence record's condition_results array."
                )
            seen.add(entry.condition_id)
        return self

    @model_validator(mode="after")
    def _check_condition_error_forces_rule_error(self) -> TraceRuleEvidence:
        if self.condition_results and self.rule_result is not RuleResult.ERROR:
            if any(entry.result is TraceConditionResult.ERROR for entry in self.condition_results):
                raise ValueError(
                    "TraceRuleEvidence.rule_result must be 'error' when any "
                    "condition_results entry has result 'error'; a rule cannot be "
                    "reported matched or not_matched while one of its own conditions "
                    "could not be evaluated."
                )
        return self
