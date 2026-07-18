"""
basis_core.decisions.operation_aware — the operation-aware authorization
request model.

This module is the fourth production module added under `src/basis_core/`
for `basis-core` v0.2.0 (see
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`, Milestone 2,
PR 8 — "OperationAwareDecisionRequest value object"), after PR 5's
`domain/operation_aware_vocabulary.py`, PR 6's `domain/evidence.py`, and
PR 7's `domain/operation_aware.py`. It implements the full request shape
published by `basis-schemas` v0.2.0's `operation-aware-decision-request`
contract (ADR-0001 §3; ADR-0005 §4, "PR C"):

  OperationAwareDecisionRequest  The additive, richer sibling of the
                                 first-wave `DecisionRequest`
                                 (`decisions/models.py`), assembling flat
                                 scalar fields with PR 6's evidence-reference
                                 models and PR 7's six context value objects.
  OperationIntent                Closed, three-value vocabulary
                                 (`read_only` / `state_changing` /
                                 `control_affecting`) for the request's
                                 `operation_intent` field — the one field on
                                 this contract with a closed enum rather than
                                 an open string label.
  OperationAwareFailureReason    Closed, six-value governed evaluator
                                 failure-category vocabulary (ADR-0002 §14),
                                 added by PR 27A
                                 (`docs/implementation/basis-core-v0.2-
                                 operation-aware-plan.md`, Milestone 9) as
                                 shared operation-aware evaluation-result
                                 vocabulary — see "Shared evaluation-result
                                 vocabulary ownership" below for why it
                                 lives here rather than in `policy/` or
                                 `audit/`.

Additive sibling, not a replacement
────────────────────────────────────
`OperationAwareDecisionRequest` does not modify, extend, subclass, migrate,
or version `decisions/models.py`'s `DecisionRequest` in any way.
`DecisionRequest` remains published, behaviorally unchanged, and this module
does not import from `decisions/models.py` except to reuse two already-
compiled validation patterns (see "Pattern reuse" below). The two request
types coexist as separate, unrelated Pydantic models with separate field
sets, separate required/optional shapes, and separate call sites.

Shared evaluation-result vocabulary ownership (`OperationAwareFailureReason`)
──────────────────────────────────────────────────────────────────────────────
`decisions` is the lowest common legal dependency shared by every kernel
subpackage that will eventually need to speak this failure vocabulary:

    policy     → decisions
    audit      → decisions
    evaluation → decisions, policy, audit

`OperationAwareFailureReason` classifies why operation-aware evaluation
could not reach an authorization outcome at all (ADR-0002 §14) — the six
governed categories `invalid_request`, `unsupported_schema_version`,
`invalid_policy_bundle`, `policy_validation_failure`,
`condition_evaluation_error`, and `internal_evaluation_error`. This is
shared evaluation-*result* vocabulary, not a request-shape concept and not
this module's own invention: it is consumed by (or will be consumed by,
per the roadmap plan) policy-owned aggregation (PR 27,
`policy/operation_aware/aggregation.py`), the future evaluation-owned
orchestrator (PR 27B), the future `OperationAwareDecisionResponse` (PR 29,
which this module will also own), trace assembly's vocabulary mapping
(PR 26), response assembly (PR 31), and audit-evidence assembly
(Milestone 10). None of those consumers may legally import from each
other for this purpose — `policy` and `audit` are mutually isolated
siblings (`docs/import-boundaries.md`), and `decisions` must never be made
to depend on `policy` (or on `audit`, or on `evaluation`) to close that
gap. Placing the vocabulary at the one subpackage every future consumer
already legally imports — `decisions` — is what lets each of them share
one definition without any of the alternatives: `policy` defining it and
`audit`/`evaluation` importing `policy` (not permitted); `audit` defining
it and `policy` importing `audit` (not permitted, and the historical
mistake this exact vocabulary previously made — see
`audit/operation_aware/evaluation_trace.py`'s own, distinct
`TraceFailureReason`, which predates this decision and is deliberately
left unchanged and unmoved, see "Audit separation" below); or two
independently-defined, value-parity-tested local copies in both `policy`
and `audit` (workable, but an unnecessary third definition once one
legally shared location already exists).

`decisions` does not gain a dependency on `policy` to host this type —
`OperationAwareFailureReason` is a closed value vocabulary with no
behavior of its own (like `OperationIntent` above), authored directly in
this module, not imported from anywhere the "may import" side of the
dependency graph would forbid.

Audit separation
─────────────────
`basis_core.audit.operation_aware.evaluation_trace.TraceFailureReason`
(PR 25) remains exactly where it is — audit's own bounded evidence
representation of this same failure vocabulary — and is not moved, removed,
or redefined by this module. `audit/` continues to define its own local
copy, value- and member-name-parity-tested against this module's
`OperationAwareFailureReason`, rather than importing it directly, because
`audit/` may import only `domain/` and `decisions/` per
`docs/import-boundaries.md` — importing `OperationAwareFailureReason` from
`decisions/operation_aware.py` into `audit/operation_aware/
evaluation_trace.py` would in fact be a legal edge on that graph, but this
module does not require or assume `audit/` makes that change; `audit/`
keeping its own local definition (as it already does for
`TraceBundleApplicability`, `TraceRuleEffect`, and every other
policy-parity vocabulary it carries) remains equally valid, and changing
that is explicitly out of scope for this PR. What remains categorically
forbidden, unchanged by this decision, is `audit/` importing `policy/`, or
`policy/` importing `audit/` — that boundary is untouched here.

Structural validation only — no evaluation behavior
──────────────────────────────────────────────────────
This module implements construction-time structural validation only. It
does not implement, and must never be extended in this PR to implement:
  - policy evaluation, authorization behavior, or policy semantics
  - condition operators or request matching against policy
  - policy bundles or policy rules
  - decision responses (`OperationAwareDecisionResponse` is later,
    separately-scoped roadmap work)
  - evaluation traces or audit evidence
  - enforcement or gateway behavior
  - runtime request assembly (basis-gateway's job, per the contract's own
    `composition.assembled_by` field)
  - cross-field consistency checks between `resource` and `resource_type`,
    between this request's `request_id`/`correlation_id` and a nested
    evidence reference's same-named fields, or between `identity_source`
    and `identity_evidence_reference.identity_source` — the contract's own
    `provenance_association` block states the parent request's field is
    authoritative and explicitly implements no automatic reconciliation.
  - `OperationAwareFailureReason` itself implements no evaluation
    behavior — it is a closed value vocabulary only, exactly like
    `OperationIntent`; this module's own aggregation/evaluation-triggering
    logic remains entirely out of scope, unchanged by this addition.

Pattern reuse — no second action/resource grammar
──────────────────────────────────────────────────
The published contract's `action_pattern` and `resource_pattern` are
byte-identical to the patterns `decisions/models.py` already compiles and
enforces on the v0.1-era `DecisionRequest` (`_ACTION_RE`, `_RESOURCE_ID_RE`).
Per the contract's own "reuses unchanged" language (§15-16) and this
repository's `resource.py`/`decisions/models.py` precedent of intentionally
duplicating simple patterns rather than creating a shared-pattern module,
this module imports those two compiled patterns directly from
`decisions/models.py` rather than compiling a second, potentially divergent
copy. `resource_type` and `authority_mode`, by contrast, use the contract's
`open_identifier_pattern` — a distinct, open (non-closed-vocabulary) label
pattern that has no v0.1.0 analog to reuse from, so it is reproduced locally
here, matching the same reproduction already made independently in
`domain/evidence.py` (`_PROTOCOL_RE`) and `domain/operation_aware.py`
(`_OPEN_IDENTIFIER_RE`).

`resource_type` is deliberately not `basis_core.domain.resource.ResourceType`
────────────────────────────────────────────────────────────────────────────
`resource_type` on this request is an open, normalized string
classification, validated only against `open_identifier_pattern` — not the
closed `ResourceType` enum `domain/resource.py` defines for the v0.1.0
kernel. This module does not import, coerce into, or validate against that
enum, and does not derive `resource_type` from `resource` or check that the
two are consistent when both are present (see "Structural validation only"
above).

Deliberately absent fields
────────────────────────────
This request has no `context`, `resource_id`, `timestamp`, `reason_code`,
`redaction_classification`, `metadata`, `extensions`, or other free-form
extension bag — the contract intentionally replaces the v0.1-era generic
`context: dict[str, str]` catch-all with governed, explicit, named context
categories (`location`, `device`, `protocol_context`, `safety_context`,
`environment_context`, `risk_context`) instead of extending it. The model's
`extra="forbid"` configuration is also what rejects every raw-secret-shaped
field this contract explicitly disallows (`access_token`, `id_token`,
`refresh_token`, `jwt`, `bearer_token`, `authorization_header`, `cookie`,
`session_secret`, `client_secret`, `password`, `private_key`, `api_key`,
`raw_claims`, `full_claim_set`, `raw_payload`, `raw_protocol_payload`,
`packet`, `frame`, `device_secret`, and any other field this contract does
not name) — no field-specific redaction logic is implemented or required;
an unknown field is simply rejected as unknown.

Not implemented by this module (deferred to later, separately-scoped
roadmap PRs): request-level exhaustive serialization/round-trip fixture
coverage (PR 9, `tests/operation_aware/test_decision_request_roundtrip.py`);
any policy, condition, selector, trace, audit, or evaluator behavior
(Milestone 4 onward); `OperationAwareDecisionResponse` (Milestone 10).

Public API status: internal to the operation-aware package for now, exactly
like `operation_aware_vocabulary` (PR 5), `evidence` (PR 6), and
`operation_aware` (PR 7). Not re-exported from `basis_core.decisions` or any
other package `__init__.py`; see `docs/public-api.md`'s "Open API
questions" convention and Section 6 of the roadmap plan for when
operation-aware symbols are expected to graduate to the stable public API
(Milestone 11, PR 35).
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field, field_validator

from basis_core.decisions.models import _ACTION_RE, _RESOURCE_ID_RE
from basis_core.domain.evidence import AdapterEvidenceReference, IdentityEvidenceReference
from basis_core.domain.operation_aware import (
    OperationAwareDevice,
    OperationAwareEnvironmentContext,
    OperationAwareLocation,
    OperationAwareProtocolContext,
    OperationAwareRiskContext,
    OperationAwareSafetyContext,
)

# Open, lowercase, deployment-defined label pattern — reproduced verbatim
# from the vendored `operation-aware-decision-request` contract's
# `open_identifier_pattern` (identical, byte-for-byte, to that contract's
# `resource_type_pattern`, which is why this one compiled pattern is reused
# for both `resource_type` and `authority_mode` below). Duplicated locally
# by design rather than imported from `domain/operation_aware.py`'s private
# `_OPEN_IDENTIFIER_RE` or `domain/evidence.py`'s private `_PROTOCOL_RE` —
# matching this repository's existing precedent (`decisions/models.py`'s
# module docstring) of intentionally duplicating simple, stable patterns
# per-module rather than creating a shared-pattern import.
_OPEN_IDENTIFIER_RE = re.compile(r"^[a-z][a-z0-9_-]*$")


def _require_non_empty(value: str, *, field_name: str) -> str:
    """Shared non-empty/non-whitespace-only check for required string
    fields (`request_id`, `subject_id`)."""
    if not value.strip():
        raise ValueError(
            f"OperationAwareDecisionRequest.{field_name} must not be empty or whitespace-only."
        )
    return value


def _require_non_empty_if_present(value: str | None, *, field_name: str) -> str | None:
    """Shared non-empty check for optional string fields that, per the
    published contract, must be non-empty *when present* (`identity_source`,
    `expected_policy_version`, and — combined with the open-identifier
    pattern check — `authority_mode`/`resource_type`)."""
    if value is not None and not value.strip():
        raise ValueError(
            f"OperationAwareDecisionRequest.{field_name} must not be empty or "
            "whitespace-only when provided."
        )
    return value


def _require_open_identifier_if_present(value: str | None, *, field_name: str) -> str | None:
    """Shared open-identifier-pattern check for optional string fields that,
    per the published contract, must match `open_identifier_pattern` when
    present (`authority_mode`, `resource_type`)."""
    value = _require_non_empty_if_present(value, field_name=field_name)
    if value is None:
        return value
    if not _OPEN_IDENTIFIER_RE.match(value):
        raise ValueError(
            f"OperationAwareDecisionRequest.{field_name} {value!r} does not match the "
            r"required pattern '^[a-z][a-z0-9_-]*$' (open, lowercase, deployment-defined "
            "label)."
        )
    return value


class OperationIntent(str, Enum):
    """
    Closed, three-value vocabulary for whether an operation is read-only,
    state-changing, or command/control-affecting — the request's
    `operation_intent` field.

    A concept distinct from, and complementary to, the `action` verb.
    Closed to these three values because ADR-0001 and the operation-aware
    authorization and policy/rule-model documents name exactly these three
    categories consistently and without qualification. Not an enforcement
    command, an obligation, or executable behavior — purely descriptive
    classification for future policy matching. This enum implements no
    interpretation of its own values; nothing in this module attaches
    authorization behavior to any member.
    """

    READ_ONLY = "read_only"
    STATE_CHANGING = "state_changing"
    CONTROL_AFFECTING = "control_affecting"


class OperationAwareFailureReason(str, Enum):
    """
    Closed, six-value governed evaluator failure-category vocabulary
    (ADR-0002 §14) — shared operation-aware evaluation-result vocabulary,
    not a request-shape field. See this module's docstring, "Shared
    evaluation-result vocabulary ownership", for why this type lives here
    rather than in `policy/operation_aware/` or
    `audit/operation_aware/evaluation_trace.py`.

    Classifies why operation-aware evaluation could not reach an
    authorization outcome at all, distinct from a substantive `allow` /
    `deny` / `not_applicable` outcome and distinct from the open-format,
    machine-readable `reason_code` (`basis_core.domain.
    operation_aware_vocabulary.ReasonCode`) that explains a *completed*
    outcome. Value- and member-name-parity-tested against
    `basis_core.audit.operation_aware.evaluation_trace.TraceFailureReason`
    (that module's own, independently-defined local copy — see "Audit
    separation" above); this module's copy is authoritative for any future
    consumer that legally imports `decisions/` but not `audit/`.

    INVALID_REQUEST              Request-level structural or semantic
                                  validation failed. Not producible by
                                  policy-owned aggregation
                                  (`aggregate_policy_outcome`) — request
                                  validation happens upstream of it.
    UNSUPPORTED_SCHEMA_VERSION   The request's implicit contract version is
                                  unsupported. Not producible by
                                  policy-owned aggregation.
    INVALID_POLICY_BUNDLE        Policy bundle structural validation
                                  failed (PR 15's responsibility). Not
                                  producible by policy-owned aggregation,
                                  which assumes a bundle already passed
                                  validation.
    POLICY_VALIDATION_FAILURE    Policy bundle semantic validation failed
                                  (PR 15's responsibility). Not producible
                                  by policy-owned aggregation, for the same
                                  reason as `INVALID_POLICY_BUNDLE`.
    CONDITION_EVALUATION_ERROR   A rule's condition evaluation could not be
                                  completed. The one member policy-owned
                                  aggregation (PR 27,
                                  `aggregate_policy_outcome`) actually
                                  constructs today, whenever any evaluated
                                  rule's `RuleConditionResult` is `ERROR`.
    INTERNAL_EVALUATION_ERROR    An unexpected internal evaluator error.
                                  Not producible by policy-owned
                                  aggregation.
    """

    INVALID_REQUEST = "invalid_request"
    UNSUPPORTED_SCHEMA_VERSION = "unsupported_schema_version"
    INVALID_POLICY_BUNDLE = "invalid_policy_bundle"
    POLICY_VALIDATION_FAILURE = "policy_validation_failure"
    CONDITION_EVALUATION_ERROR = "condition_evaluation_error"
    INTERNAL_EVALUATION_ERROR = "internal_evaluation_error"


class OperationAwareDecisionRequest(BaseModel):
    """
    The operation-aware authorization request — an additive, richer sibling
    of `decisions.models.DecisionRequest` carrying the operational context
    an operation-aware `basis-core` v0.2.0 evaluator will reason about.

    This model implements structural validation only: field presence,
    type, and pattern/enum shape. It performs no evaluation, no policy
    matching, no evidence retrieval, no protocol parsing, no risk or safety
    calculation, and no cross-field reconciliation. See this module's
    docstring for the full list of what is deliberately out of scope.

    Required fields
    ───────────────
    request_id  Unique identifier for this evaluation request. Non-empty.
                Not auto-generated — the producer (basis-gateway) supplies
                the request identity; unlike `DecisionRequest.request_id`,
                this field has no default factory.
    subject_id  Stable identifier of the requesting subject. Non-empty.
    action      The composite action, in the canonical
                `{verb}:{domain}[:{object}]` form. Non-empty; validated with
                the same compiled pattern `decisions/models.py` already
                enforces for `DecisionRequest.action`.

    Optional fields
    ───────────────
    correlation_id             Passed through verbatim; no format
                                constraint beyond string-or-`None`.
    subject_roles               Role names held by the subject. Defaults to
                                an empty list. Unlike `DecisionRequest`'s
                                runtime normalization (sort/dedupe/strip),
                                this contract does not restate that
                                normalization as a static validation rule,
                                so items are accepted as supplied — see the
                                vendored contract's `subject_roles`
                                description.
    subject_attrs                Additional subject attributes for ABAC
                                policy conditions. Defaults to an empty
                                mapping. Keys and values are strings.
    identity_source              Opaque, provider-neutral label identifying
                                the identity source or authority. Non-empty
                                when present. Remains provider-neutral: this
                                module implements no OIDC-, SAML-, JWT-,
                                Keycloak-, Okta-, or Entra-specific
                                behavior.
    authority_mode               Opaque, deployment-defined label for the
                                identity authority mode (e.g. `"federated"`,
                                `"synchronized"`, `"standalone-air-gapped"`).
                                Open lowercase identifier, not a closed
                                enum — basis-architecture has not published
                                a governed authority-mode vocabulary.
    identity_evidence_reference  Optional `IdentityEvidenceReference`
                                (PR 6, reused directly, unmodified). Never
                                retrieves, verifies, or reconciles the
                                evidence it references.
    resource                    Optional canonical resource identifier in
                                `{resource_type}:{local_resource_id}` form.
                                Validated with the same compiled pattern
                                `decisions/models.py` already enforces for
                                `DecisionRequest.resource_id`. Named
                                `resource`, not `resource_id` — a distinct
                                field from `DecisionRequest.resource_id`,
                                which this module does not touch.
    resource_type                Open, normalized resource-type
                                classification for policy matching (e.g.
                                `"ahu"`, `"setpoint"`). Non-empty and
                                open-identifier-shaped when present. This is
                                deliberately not `domain.resource.ResourceType`
                                (a closed enum) — no coercion into that
                                enum is performed, and no cross-field
                                consistency between `resource_type` and the
                                type prefix embedded in `resource` is
                                validated or required.
    location                    Optional `OperationAwareLocation` (PR 7,
                                reused directly). No hierarchy, topology, or
                                parent/child validation.
    device                       Optional `OperationAwareDevice` (PR 7,
                                reused directly). Not assumed equivalent to
                                `resource`.
    protocol_context              Optional `OperationAwareProtocolContext`
                                (PR 7, reused directly). Evidence only; this
                                module implements no protocol parsing.
    operation_intent              Optional `OperationIntent`. Closed to
                                exactly `read_only` / `state_changing` /
                                `control_affecting`.
    adapter_evidence_reference    Optional `AdapterEvidenceReference` (PR 6,
                                reused directly, unmodified). Never
                                inspects protocol evidence or verifies
                                digests.
    safety_context                Optional `OperationAwareSafetyContext`
                                (PR 7, reused directly). No safety-state
                                inference or evaluation.
    environment_context           Optional `OperationAwareEnvironmentContext`
                                (PR 7, reused directly). No environment
                                discovery or derivation.
    risk_context                  Optional `OperationAwareRiskContext` (PR
                                7, reused directly). No risk calculation or
                                enforced numeric range.
    evaluation_time                Optional, timezone-aware timestamp
                                supplied by the producer. Timezone-naive
                                values are rejected. Never defaulted from
                                the system clock; unlike
                                `DecisionRequest.timestamp`, this field has
                                no default factory and no required-ness.
    expected_policy_version       Optional, non-empty-when-present policy
                                version label the producer expects. This
                                module implements no policy loading,
                                comparison, or selection behavior for it.
    """

    # --- Request identity and correlation --------------------------------
    request_id: str
    correlation_id: str | None = None

    # --- Subject -----------------------------------------------------------
    subject_id: str
    subject_roles: list[str] = Field(default_factory=list)
    subject_attrs: dict[str, str] = Field(default_factory=dict)
    identity_source: str | None = None
    authority_mode: str | None = None
    identity_evidence_reference: IdentityEvidenceReference | None = None

    # --- Target: action and resource ---------------------------------------
    action: str
    resource: str | None = None
    resource_type: str | None = None

    # --- Location and device -------------------------------------------------
    location: OperationAwareLocation | None = None
    device: OperationAwareDevice | None = None

    # --- Operation: protocol evidence, intent, adapter evidence -------------
    protocol_context: OperationAwareProtocolContext | None = None
    operation_intent: OperationIntent | None = None
    adapter_evidence_reference: AdapterEvidenceReference | None = None

    # --- Evaluation context: safety, environment, risk -----------------------
    safety_context: OperationAwareSafetyContext | None = None
    environment_context: OperationAwareEnvironmentContext | None = None
    risk_context: OperationAwareRiskContext | None = None
    evaluation_time: datetime | None = None

    # --- Policy ---------------------------------------------------------------
    expected_policy_version: str | None = None

    model_config = {"frozen": True, "extra": "forbid"}

    @field_validator("request_id", "subject_id", mode="after")
    @classmethod
    def ids_must_not_be_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError(
                "OperationAwareDecisionRequest.request_id/subject_id must not be empty "
                "or whitespace-only."
            )
        return v

    @field_validator("action", mode="after")
    @classmethod
    def validate_action_format(cls, v: str) -> str:
        v = _require_non_empty(v, field_name="action")
        if not _ACTION_RE.match(v):
            raise ValueError(
                f"OperationAwareDecisionRequest.action {v!r} does not match the required "
                "format '{verb}:{domain}[:{object}]' (e.g. 'write:hvac:setpoint', "
                "'read:audit:log'). Segments must be lowercase and separated by colons."
            )
        return v

    @field_validator("resource", mode="after")
    @classmethod
    def validate_resource_format(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if not _RESOURCE_ID_RE.match(v):
            raise ValueError(
                f"OperationAwareDecisionRequest.resource {v!r} does not match the required "
                "format '{resource_type}:{local_resource_id}' (e.g. 'hvac:zone-a', "
                "'ahu:rooftop-1'). Type prefix and all qualifier segments must be "
                "lowercase. Segments are separated by colons."
            )
        return v

    @field_validator("resource_type", mode="after")
    @classmethod
    def validate_resource_type(cls, v: str | None) -> str | None:
        return _require_open_identifier_if_present(v, field_name="resource_type")

    @field_validator("identity_source", mode="after")
    @classmethod
    def validate_identity_source(cls, v: str | None) -> str | None:
        return _require_non_empty_if_present(v, field_name="identity_source")

    @field_validator("authority_mode", mode="after")
    @classmethod
    def validate_authority_mode(cls, v: str | None) -> str | None:
        return _require_open_identifier_if_present(v, field_name="authority_mode")

    @field_validator("expected_policy_version", mode="after")
    @classmethod
    def validate_expected_policy_version(cls, v: str | None) -> str | None:
        return _require_non_empty_if_present(v, field_name="expected_policy_version")

    @field_validator("evaluation_time", mode="after")
    @classmethod
    def evaluation_time_must_be_tz_aware(cls, v: datetime | None) -> datetime | None:
        if v is not None and v.tzinfo is None:
            raise ValueError(
                "OperationAwareDecisionRequest.evaluation_time must be timezone-aware "
                "when provided (e.g. '2026-05-22T14:30:00Z' or "
                "'2026-05-22T14:30:00-06:00'). No system-clock default is applied by "
                "this model."
            )
        return v
