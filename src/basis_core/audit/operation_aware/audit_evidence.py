"""
basis_core.audit.operation_aware.audit_evidence — the `AuditEvidence` data
model.

This is the fourth module added under `src/basis_core/audit/operation_aware/`
(see `docs/implementation/basis-core-v0.2-operation-aware-plan.md`, Milestone
10, PR 30 — "AuditEvidence model"), after PR 24's `trace_rule_evidence.py`
and PR 25's `evaluation_trace.py`. It implements the published shape from
`basis-schemas` v0.2.1's `audit-evidence` contract (ADR-0003 §2, §14):

  AuditEvidence   The bounded, durable, kernel-side evidence record of one
                  operation-aware authorization evaluation.

Scope — what `AuditEvidence` is, and is not
────────────────────────────────────────────────────────────────────────────
Per the vendored contract's own file header: "Trace explains evaluation.
Audit records evidence. Gateway enforcement records what happened at
runtime." `AuditEvidence` is bounded kernel-side evidence for one
operation-aware authorization evaluation. It is not:

  - `EvaluationTrace` (`evaluation_trace.py`, PR 25) — the detailed,
    per-rule explanation artifact. `AuditEvidence` may reference a trace by
    `trace_id`; it never embeds `EvaluationTrace`, `TraceRuleEvidence`, or
    any condition-level evidence.
  - `GatewayAuditEvent` — the gateway's own enforcement-boundary event,
    combining this kernel-produced evidence with gateway-only enforcement
    facts. Not implemented by this module or this PR; `AuditEvidence`
    carries no enforcement action, enforcement result, or gateway-runtime
    fact of any kind.
  - the v0.1 `basis_core.audit.events.AuditEvent` — a structurally distinct,
    unrelated, unmodified family. See "v0.1 separation" below.
  - an audit writer, a persistence mechanism, or an enforcement record — see
    "No persistence" below.

This module performs no audit assembly, no response assembly, no engine
invocation, no trace derivation, no ID generation, and no clock or random
access; it only validates an already-produced audit evidence record.

No persistence
────────────────────────────────────────────────────────────────────────────
`AuditEvidence` is produced by `basis-core` as part of one evaluation's
artifacts (alongside `OperationAwareDecisionResponse` and, optionally,
`EvaluationTrace`) — see the vendored contract's `composition` block:
`produced_by: basis-core`, `assembled_by: basis-gateway` (into a
`GatewayAuditEvent`, a separate, later, gateway-owned contract). This module
defines the record shape only. It adds no `write`/`save`/`store`/`append`/
`publish`/`emit`/`persist` method, no `AuditWriter`-shaped protocol for this
type, and no storage backend. Persistence, retention, signing, and
tamper-evidence are explicitly out of scope for this contract (see the
vendored YAML's own header and `constraints` block) and for this PR.

v0.1 separation
────────────────────────────────────────────────────────────────────────────
`basis_core.audit.events.AuditEvent` (and `AUDIT_SCHEMA_VERSION`,
`AuditEventType`, `AuditOutcome`) and `basis_core.audit.writer.AuditWriter`
(and `NullAuditWriter`, `LogAuditWriter`) are not modified, subclassed, or
reinterpreted by this module. `AuditEvidence` is a distinct symbol with a
distinct field set, never aliased to `AuditEvent`, never accepted by the
existing `AuditWriter` protocol or its reference implementations, and never
exported from the same module. See `tests/operation_aware/
test_audit_evidence.py::TestV01Compatibility` for the mechanically-checked
regression proof.

Shared evaluation-state vocabulary — reused, not redefined
────────────────────────────────────────────────────────────────────────────
`evaluation_status`, `outcome`, and `failure_reason` reuse the
decisions-owned vocabularies added by PR 29
(`basis_core.decisions.operation_aware.OperationAwareEvaluationStatus`,
`.OperationAwareDecisionOutcome`, `.OperationAwareFailureReason`) directly —
this module does not define a fourth, audit-local copy of any of these three
enums the way `evaluation_trace.py` (PR 25) independently defined its own
`EvaluationStatus`/`TraceOutcome`/`TraceFailureReason`. That module's own
docstring ("Vocabulary ownership") explains why it *had* to hold a local
copy at the time it was written: `audit/` may import only `domain/` per
`docs/import-boundaries.md`'s permission matrix. That matrix, however, has
always additionally permitted `audit/` to import `decisions/` — an edge
`docs/import-boundaries.md` itself calls out as architecture-ceiling
alignment "documented ... not a new runtime dependency" because, until this
module, no `audit/` module actually exercised it. This module is the first
to do so: it imports `OperationAwareEvaluationStatus`,
`OperationAwareDecisionOutcome`, and `OperationAwareFailureReason` directly
from `basis_core.decisions.operation_aware`, turning a previously-documented
but unexercised permission into an actual import. This does not change
`evaluation_trace.py`'s own local vocabulary — that module is left exactly
as PR 25 landed it (see that module's docstring; not revisited or migrated
by this PR). `reason_code` similarly reuses
`basis_core.domain.operation_aware_vocabulary.ReasonCode` unchanged, via the
same small `PlainValidator`/`PlainSerializer` wrapper this package's sibling
modules (`trace_rule_evidence.py`, `evaluation_trace.py`) and
`evaluation/operation_aware/response.py` already use — reproduced locally
here rather than imported, for the same "no shared private wrapper across
independently-scoped modules" reasoning those modules' docstrings give.

Evaluation-state invariants (this record's own fields)
────────────────────────────────────────────────────────────────────────────
Mirrors `EvaluationTrace`'s and `OperationAwareDecisionResponse`'s own
`outcome`/`failure_reason` invariants exactly (ADR-0002 §14):

  1. `outcome` is null if and only if `evaluation_status` is `failed`.
  2. `failure_reason` is non-null if and only if `evaluation_status` is
     `failed`.

A failed evaluation can therefore never serialize a non-null `outcome` —
evaluation failure is never silently normalized into a substantive `deny`.
This module supplies no default `outcome` or `failure_reason`; both must be
supplied explicitly by the caller (audit-evidence assembly, PR 31) for every
construction. Unlike `EvaluationTrace`, this contract publishes no
`bundle_applicability` field, so there is no third invariant to enforce here
(see the vendored contract's `required`/`fields` blocks — `evidence_id`,
`request_id`, `evaluation_status`, `outcome`, `failure_reason`, and
`recorded_at` are this record's only required keys).

Required-nullable serialization
────────────────────────────────────────────────────────────────────────────
`outcome` and `failure_reason` are required keys whose value may be `None` —
the same required-nullable shape `EvaluationTrace.outcome`/
`bundle_applicability` (PR 25) and `OperationAwareDecisionResponse.outcome`/
`.failure_reason` (PR 29) already have. Pydantic's `exclude_none=True` drops
any `None`-valued key regardless of whether the field is required, so a
plain `model_dump(exclude_none=True)` would make "evaluation failed" (both
null) indistinguishable from "field omitted." This module follows both
prior models' proven `@model_serializer(mode="wrap")` pattern (not a
`model_dump` override, which would neither fire for `model_dump_json` nor
for this model nested inside a parent model's own `model_dump`/
`model_dump_json`) to restore `outcome`/`failure_reason` as explicit `null`
whenever `exclude_none` alone caused their omission — never when the
caller's own `include`/`exclude` selection excluded them.

Caller-supplied identity and `recorded_at` — no generation
────────────────────────────────────────────────────────────────────────────
`evidence_id`, `request_id`, `trace_id`, `correlation_id`, `bundle_id`, and
`bundle_version` are all caller-supplied; none has a default factory, and
none is derived, generated, or normalized beyond the structural checks below
(non-empty, semver pattern where applicable). `recorded_at` is a required,
non-nullable, timezone-aware timestamp — distinct from
`OperationAwareDecisionRequest.evaluation_time` (request-supplied context the
evaluator reasons about) and from any request-side timestamp — supplied by
the caller only. This module has no default factory for it, does not call
`datetime.now()`, does not derive it from any other field, and does not
substitute evaluation time as recording time. A timezone-naive value is
rejected, mirroring `OperationAwareDecisionRequest.evaluation_time`'s own
tz-aware check (`decisions/operation_aware.py`) and
`basis_core.audit.events.AuditEvent.timestamp`'s existing v0.1 precedent.

`matched_rule_ids` — validated, not derived
────────────────────────────────────────────────────────────────────────────
`matched_rule_ids` is a bounded list of caller-supplied `rule_id` values.
This model validates the supplied list (non-empty items, no duplicates,
caller-supplied order preserved exactly — array position is never
authorization precedence, per the vendored contract's own description); it
does not derive, calculate, sort, or deduplicate the list from
`EvaluationTrace`, policy rules, the response, or engine internals. That
derivation belongs to audit-evidence assembly (PR 31), not this model.

Evidence references — typed, reference-only
────────────────────────────────────────────────────────────────────────────
`identity_evidence_reference` and `adapter_evidence_reference` reuse
`basis_core.domain.evidence.IdentityEvidenceReference`/
`.AdapterEvidenceReference` (PR 6) unchanged and unmodified — real typed
models, never `dict[str, Any]` or another untyped mapping. Both are
references only: this module does not fetch, resolve, or verify the
evidence either one points to. Neither this model nor either reference type
admits a raw access token, ID token, refresh token, JWT, bearer token,
authorization header, cookie, session secret, client secret, password,
private key, API key, raw claim set, or raw protocol payload — no such
field exists anywhere in this shape, and `extra="forbid"` rejects any
attempt to smuggle one in under an unanticipated name.

Import boundary
────────────────────────────────────────────────────────────────────────────
This module imports from `basis_core.decisions.operation_aware` (the three
shared evaluation-state enums above), `basis_core.domain.evidence` (the two
evidence-reference models), and `basis_core.domain.operation_aware_vocabulary`
(`ReasonCode`) — all legal per `docs/import-boundaries.md` (`audit/` may
import `domain/` and `decisions/`). It does not import
`basis_core.policy`, `basis_core.evaluation`, `basis_core.enforcement`, or
`basis_core.adapters` — no type from any of those layers is needed to define
this record's shape, and importing any of them would violate the audit/
import boundary (`audit/` must not import `policy/`, `evaluation/`,
`adapters/`, or `enforcement/`). In particular, this module does not import
`OperationAwareDecisionResponse` (`evaluation/operation_aware/response.py`)
merely to reuse its validation behavior — the two invariant checks below are
implemented directly, independently, on this model.

Relationship to `OperationAwareDecisionResponse`
────────────────────────────────────────────────────────────────────────────
This module does not embed, import, or construct
`OperationAwareDecisionResponse`, and does not enforce complete
response/audit-evidence field equality. `AuditEvidence` validates its own
internal correctness only; audit-evidence assembly from a response/trace
pair (PR 31) and full response/trace/audit-evidence agreement (PR 32) are
both later, separately-scoped roadmap work.

Public API status: internal to the operation-aware package, exactly like
every other operation-aware module added so far. Not re-exported from
`basis_core.audit`, `basis_core`, or any other package `__init__.py`; public
API stabilization is Milestone 11, PR 35.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated, Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PlainSerializer,
    PlainValidator,
    SerializationInfo,
    SerializerFunctionWrapHandler,
    field_validator,
    model_serializer,
    model_validator,
)

from basis_core.decisions.operation_aware import (
    OperationAwareDecisionOutcome,
    OperationAwareEvaluationStatus,
    OperationAwareFailureReason,
)
from basis_core.domain.evidence import AdapterEvidenceReference, IdentityEvidenceReference
from basis_core.domain.operation_aware_vocabulary import ReasonCode

__all__ = ["AUDIT_EVIDENCE_SCHEMA_VERSION", "AuditEvidence"]


#: The audit-evidence *instance* format version this module produces when a
#: caller does not supply one — distinct from this module's own contract
#: shape version (`audit-evidence.yaml`'s `contract.version`) and from the
#: `basis-schemas` package version, matching the three-way distinction
#: `policy-bundle.yaml`/`PolicyBundle.schema_version` already draws (see
#: `policy/operation_aware/bundle.py`). This is a static, literal default —
#: not a generated or computed value — mirroring the vendored contract's own
#: published `default: "0.1.0"` for this field.
AUDIT_EVIDENCE_SCHEMA_VERSION = "0.1.0"


def _require_non_empty(value: str, *, field_name: str) -> str:
    """Shared non-empty/non-whitespace-only check for required string
    fields (`evidence_id`, `request_id`)."""
    if not value.strip():
        raise ValueError(f"AuditEvidence.{field_name} must not be empty or whitespace-only.")
    return value


def _require_non_empty_if_present(value: str | None, *, field_name: str) -> str | None:
    """Shared non-empty check for optional string fields that must be
    non-empty *when present* (`trace_id`, `bundle_id`, `explanation`)."""
    if value is not None and not value.strip():
        raise ValueError(
            f"AuditEvidence.{field_name} must not be empty or whitespace-only when provided."
        )
    return value


# Reproduced locally rather than imported — this repository's convention for
# simple, stable patterns is to duplicate them per module rather than share a
# compiled copy across packages that must not import from one another (see
# `EvaluationTrace._BUNDLE_VERSION_RE` and
# `OperationAwareDecisionResponse._BUNDLE_VERSION_RE`, reproduced identically
# here).
_BUNDLE_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")

# Reproduced from the vendored contract's own `schema_version_pattern` —
# identical shape to `_BUNDLE_VERSION_RE` above, kept as a separate compiled
# pattern (not reused) because the two fields are independently governed and
# could diverge in a future contract revision.
_SCHEMA_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")


# `reason_code` reuses `ReasonCode` (domain-layer) structurally via a small
# `PlainValidator`/`PlainSerializer` wrapper. Identical wrappers already
# exist in this package's sibling modules (`trace_rule_evidence.py`,
# `evaluation_trace.py`) and in `evaluation/operation_aware/response.py`;
# reproduced here rather than imported to keep this module's reason-code
# integration self-contained, matching those modules' own stated reasoning.


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


#: Fields that are *required keys* on every `AuditEvidence` but whose
#: *value* may be `null` — see the module docstring, "Required-nullable
#: serialization." Every other nullable field on this model is optional
#: (defaults to `None` when absent) and is left to Pydantic's normal
#: `exclude_none` behavior by the serializer below.
_REQUIRED_NULLABLE_FIELDS: tuple[str, ...] = ("outcome", "failure_reason")


class AuditEvidence(BaseModel):
    """
    Bounded, durable, kernel-side evidence record of one operation-aware
    authorization evaluation — see the module docstring for scope, field
    shape, required-nullable behavior, shared vocabulary reuse, the
    evaluation-state invariant, `matched_rule_ids`/evidence-reference
    behavior, and serialization.

    Required fields
    ────────────────
    evidence_id        Stable identifier for this audit evidence record.
                       Non-empty. Caller-supplied; never generated.
    request_id          The request_id of the operation-aware-decision-
                       request/response this evidence records. Non-empty.
    evaluation_status   `OperationAwareEvaluationStatus.COMPLETED` or
                       `.FAILED`.
    outcome             `OperationAwareDecisionOutcome` or `None`.
                       Required-nullable: the key is always present; the
                       value is `None` if and only if `evaluation_status`
                       is `failed`.
    failure_reason       `OperationAwareFailureReason` or `None`.
                       Required-nullable: non-`None` if and only if
                       `evaluation_status` is `failed`.
    recorded_at          Timezone-aware timestamp of when this record was
                       produced. Caller-supplied; never generated from a
                       clock, never derived from any other field.

    Optional fields
    ────────────────
    correlation_id       Passed through verbatim; no format constraint
                        beyond string-or-`None`.
    trace_id             The trace_id of the `EvaluationTrace` that explains
                        this evidence's evaluation, when one was produced
                        and the producer chooses to reference it by
                        identifier. Reference only — never embeds a full
                        `EvaluationTrace`. Non-empty when present.
    bundle_id            The bundle_id of the policy bundle actually
                        evaluated, when one applied. Non-empty when
                        present.
    bundle_version       The bundle_version of the policy bundle actually
                        evaluated. Semver-shaped when present.
    matched_rule_ids      Bounded list of stable rule_id values whose
                        evaluation-trace rule_evidence entry carried
                        rule_result: matched. Validated, not derived — see
                        the module docstring. Defaults to an empty list.
                        Items must be non-empty and unique; caller-supplied
                        order is preserved exactly.
    identity_evidence_reference  Optional `IdentityEvidenceReference` (PR
                        6, reused directly). Never retrieves, verifies, or
                        reconciles the evidence it references.
    adapter_evidence_reference    Optional `AdapterEvidenceReference` (PR 6,
                        reused directly). Never inspects protocol evidence
                        or verifies digests.
    reason_code           Optional `ReasonCode`, reused unchanged. Not
                        required to equal the response's own reason_code
                        (see the field's own description in the vendored
                        contract).
    explanation           Optional, non-empty-when-present static
                        explanation string. Descriptive rendering only —
                        never authoritative over evaluation_status/
                        outcome/failure_reason.
    schema_version        The audit-evidence instance format version this
                        record was produced against. Defaults to
                        `AUDIT_EVIDENCE_SCHEMA_VERSION` ("0.1.0") when
                        omitted, matching the vendored contract's own
                        published default; a static literal, never
                        computed or generated at construction time.
    """

    evidence_id: str
    request_id: str
    correlation_id: str | None = None
    trace_id: str | None = None
    evaluation_status: OperationAwareEvaluationStatus
    outcome: OperationAwareDecisionOutcome | None
    failure_reason: OperationAwareFailureReason | None
    bundle_id: str | None = None
    bundle_version: str | None = None
    matched_rule_ids: list[str] = Field(default_factory=list)
    identity_evidence_reference: IdentityEvidenceReference | None = None
    adapter_evidence_reference: AdapterEvidenceReference | None = None
    reason_code: ReasonCodeField = None
    explanation: str | None = None
    recorded_at: datetime
    schema_version: str = AUDIT_EVIDENCE_SCHEMA_VERSION

    model_config = ConfigDict(frozen=True, extra="forbid")

    # ── Field-level validation ───────────────────────────────────────────

    @field_validator("evidence_id", mode="after")
    @classmethod
    def _evidence_id_must_not_be_empty(cls, v: str) -> str:
        return _require_non_empty(v, field_name="evidence_id")

    @field_validator("request_id", mode="after")
    @classmethod
    def _request_id_must_not_be_empty(cls, v: str) -> str:
        return _require_non_empty(v, field_name="request_id")

    @field_validator("trace_id", mode="after")
    @classmethod
    def _trace_id_must_not_be_empty_if_present(cls, v: str | None) -> str | None:
        return _require_non_empty_if_present(v, field_name="trace_id")

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
                f"AuditEvidence.bundle_version {v!r} does not match the required semver "
                r"pattern '^\d+\.\d+\.\d+$'."
            )
        return v

    @field_validator("explanation", mode="after")
    @classmethod
    def _explanation_must_not_be_empty_if_present(cls, v: str | None) -> str | None:
        return _require_non_empty_if_present(v, field_name="explanation")

    @field_validator("schema_version", mode="after")
    @classmethod
    def _schema_version_must_match_semver(cls, v: str) -> str:
        v = _require_non_empty(v, field_name="schema_version")
        if not _SCHEMA_VERSION_RE.match(v):
            raise ValueError(
                f"AuditEvidence.schema_version {v!r} does not match the required semver "
                r"pattern '^\d+\.\d+\.\d+$'."
            )
        return v

    @field_validator("recorded_at", mode="after")
    @classmethod
    def _recorded_at_must_be_tz_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError(
                "AuditEvidence.recorded_at must be timezone-aware (e.g. "
                "'2026-05-22T14:30:01Z' or '2026-05-22T14:30:01-06:00'). No system-clock "
                "default is applied by this model; the caller must always supply this "
                "value explicitly."
            )
        return v

    @field_validator("matched_rule_ids", mode="after")
    @classmethod
    def _matched_rule_ids_items_must_not_be_empty(cls, v: list[str]) -> list[str]:
        for item in v:
            if not item.strip():
                raise ValueError(
                    "AuditEvidence.matched_rule_ids must not contain an empty or "
                    "whitespace-only rule_id."
                )
        return v

    @field_validator("matched_rule_ids", mode="after")
    @classmethod
    def _matched_rule_ids_must_be_unique(cls, v: list[str]) -> list[str]:
        seen: set[str] = set()
        for rule_id in v:
            if rule_id in seen:
                raise ValueError(
                    "AuditEvidence.matched_rule_ids contains a duplicate rule_id "
                    f"{rule_id!r}; rule_id values must be unique within one record's "
                    "matched_rule_ids array."
                )
            seen.add(rule_id)
        return v

    # ── Cross-field invariants: evaluation-state matrix ──────────────────
    # Implemented directly on this model — not imported from
    # `OperationAwareDecisionResponse` or `EvaluationTrace` — per the module
    # docstring's "Import boundary": `audit/` must never import
    # `evaluation/`.

    @model_validator(mode="after")
    def _check_outcome_null_iff_failed(self) -> AuditEvidence:
        """Invariant 1 — see the module docstring."""
        if (
            self.evaluation_status is OperationAwareEvaluationStatus.FAILED
            and self.outcome is not None
        ):
            raise ValueError(
                "AuditEvidence.outcome must be null when evaluation_status is 'failed'; "
                "a failed evaluation must never serialize a non-null outcome."
            )
        if (
            self.evaluation_status is OperationAwareEvaluationStatus.COMPLETED
            and self.outcome is None
        ):
            raise ValueError(
                "AuditEvidence.outcome must be one of 'allow', 'deny', or 'not_applicable' "
                "when evaluation_status is 'completed'."
            )
        return self

    @model_validator(mode="after")
    def _check_failure_reason_null_iff_failed(self) -> AuditEvidence:
        """Invariant 2 — see the module docstring."""
        if (
            self.evaluation_status is OperationAwareEvaluationStatus.FAILED
            and self.failure_reason is None
        ):
            raise ValueError(
                "AuditEvidence.failure_reason must be non-null when evaluation_status is 'failed'."
            )
        if (
            self.evaluation_status is OperationAwareEvaluationStatus.COMPLETED
            and self.failure_reason is not None
        ):
            raise ValueError(
                "AuditEvidence.failure_reason must be null when evaluation_status is 'completed'."
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
        and `EvaluationTrace`/`OperationAwareDecisionResponse`'s identical
        pattern.

        `handler(self)` produces Pydantic's normal result for this model,
        already honoring `mode`, `include`, `exclude`, `by_alias`,
        `exclude_unset`, `exclude_defaults`, `round_trip`, and every other
        `SerializationInfo` setting unchanged, including recursively
        serializing the nested evidence-reference fields — this method
        touches nothing about that result except the two named top-level
        keys, and only when `exclude_none` is the reason either is missing:

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
