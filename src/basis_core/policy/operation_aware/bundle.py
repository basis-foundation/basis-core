"""
basis_core.policy.operation_aware.bundle — the `PolicyBundle` data model.

This module is the third module added under `src/basis_core/policy/
operation_aware/` for `basis-core` v0.2.0 (see
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`, Milestone 4,
PR 14 — "PolicyBundle model"), after PR 12's `condition.py` and PR 13's
`rule.py`. It implements exactly the shape published by `basis-schemas`
v0.2.0's `policy-bundle` contract (ADR-0004 §2-3):

  PolicyBundle        The unit of policy identity, versioning, ownership,
                       provenance, optional applicability scope, and rule
                       grouping: a stable bundle identifier, an explicit
                       bundle content version distinct from the bundle-
                       format schema version, a policy-owner/authority
                       reference, an optional structured applicability
                       scope (`PolicyBundleScope`), a non-empty collection
                       of `OperationAwarePolicyRule` (PR 13, reused
                       directly), and optional descriptive/provenance/
                       deprecation metadata.
  PolicyBundleScope   The structured, closed-shape nested `scope` object:
                       ten independently-optional selector categories
                       (`policy-bundle.yaml`'s `scope_shape`). Every
                       populated selector is a non-empty array of
                       alternatives; an entirely empty scope object is
                       invalid — the same "at least one populated
                       selector" shape `OperationAwarePolicyMatch`
                       (`rule.py`, PR 13) already establishes for `match`.

Architectural boundary — structural shape only, no evaluation, no
applicability
────────────────────────────────────────────────────────────────────────
This module publishes the bundle *shape*. It does not implement, and must
never grow:
  - bundle evaluation, rule evaluation, or condition evaluation
  - scope-to-request applicability determination (`determine_applicability
    ()`, `is_applicable()`, `matches_request()`, hierarchy/prefix/wildcard
    matching, site/building topology resolution) — that is PR 17
    (Milestone 5), a later, separately-scoped roadmap item. This module
    implements `PolicyBundleScope` as a typed *structural* model only,
    exactly as PR 13's `OperationAwarePolicyMatch` implements `match`'s
    structure without implementing rule matching.
  - bundle-level structural/semantic validation as an explicit pipeline
    (`PolicyBundleValidationError`, `validate_policy_bundle()`) — that is
    PR 15, a later, separately-scoped roadmap item. Pydantic construction
    succeeding here means the bundle is "structurally constructed" /
    "contract-shaped at the model boundary" — never "semantically valid
    policy", "approved policy", "safe policy", or "trusted policy". See
    "Deferred to PR 15" below for the one specific validation rule this
    boundary excludes.
  - bundle loading, storage, distribution, signing, signature
    verification, an approval workflow, or any deployment behavior
  - policy selection, bundle choice among candidates, or canonical
    compatibility-vector interpretation (PR 16)
  - a self-attested `validation_status` (or `valid`/`invalid`/`approved`/
    `pending`/`draft`/`checked`) field of any kind — the vendored
    contract's file header states explicitly that whether a bundle is
    valid is derived by a future `basis-core` validator/runtime process,
    never self-asserted by the bundle's own authored content
    (`policy-bundle.yaml`'s `constraints`, final entry)

Deferred to PR 15 — duplicate `rule_id` across `bundle.rules`
────────────────────────────────────────────────────────────────────────
The vendored `policy-bundle.yaml` contract publishes `rule_id` uniqueness
across a bundle's `rules` array as BUNDLE-level validation (`constraints`:
"rule_id values across this bundle's rules array must be unique. This is
BUNDLE-level validation ..."), and its own embedded `examples.invalid`
block includes one example, "duplicate rule IDs within one bundle", that
depends on this check to be rejected. The roadmap plan's PR 14 entry is
explicit that bundle-level `rule_id` uniqueness is PR 15's responsibility
("Non-goals: no bundle-level uniqueness check (that is bundle's job, PR
14)" — written from PR 13's perspective — refined by PR 14/PR 15's own
non-goals: "no stored `validation_status`; no evaluation logic" for PR 14,
and PR 15's objective naming "duplicate `rule_id` across a bundle's
`rules`" as its own explicit scope). This module therefore does NOT
implement duplicate-`rule_id` rejection — doing so here would silently
pull PR 15's semantic-validation pipeline forward. The one vendored
invalid example that depends on this check is explicitly excluded (with
this exact reason) from this module's own fixture-conformance test
(`tests/operation_aware/test_policy_bundle.py`) and from the PR 10
conformance suite's per-example enforcement
(`tests/operation_aware/test_contract_conformance.py`) — in both cases
visibly, with a documented reason, never silently dropped or disguised as
already covered by some other check. See both test modules' docstrings
for the mechanics.

Scope semantics boundary
────────────────────────────────────────────────────────────────────────
`policy-bundle.yaml`'s `scope_semantics` documents (but does not
implement) the semantic contract a future evaluator must honor: scope
absent (or explicit `null`) means globally applicable; scope present
restricts applicability to requests matching every populated selector
(all-of across selectors, any-of within one selector); a present-but-
non-matching scope resolves to `NOT_APPLICABLE` (ADR-0002 §5); an entirely
empty scope object is invalid. This module implements only the last of
those four as a structural constraint (`PolicyBundleScope` rejects an
entirely empty object) — the first three describe evaluator behavior this
module does not implement, host, or approximate in any way.

Selector representation: `None` is an internal sentinel only
────────────────────────────────────────────────────────────────────────
Exactly like `OperationAwarePolicyMatch` (`rule.py`, PR 13), every one of
`PolicyBundleScope`'s ten selector fields is typed `list[str] | None =
None`, where `None` is a purely internal "this selector was not supplied"
sentinel. `policy-bundle.yaml`'s `scope_shape` publishes each selector
field's own `type` as `array` only (no `"null"` variant) — the same
pattern `match_shape` publishes for `OperationAwarePolicyMatch`'s twenty
selectors — so the same three input states are mechanically enforced:

  key omitted entirely      → accepted; stored internally as `None`
  key present, value `null` → **rejected** (`ValidationError`)
  key present, value `[]`   → **rejected** (`ValidationError`)
  key present, non-empty
    array                   → accepted, item-validated, stored as-is

This is unlike the top-level `scope` field on `PolicyBundle` itself,
whose own published type is `[object, "null"]` (like `rule.py`'s
`match`/`conditions` fields) — an explicit top-level `scope: null` is
therefore accepted and treated identically to omission, while an explicit
`null` for any *individual selector inside* a present scope object is
rejected. See `rule.py`'s docstring, "Selector/`conditions` representation:
`None` is an internal sentinel only", for the identical reasoning this
module reuses without alteration.

Governed serialization convention: `exclude_none=True`
────────────────────────────────────────────────────────────────────────
Because every unset top-level optional field (`scope`, `description`,
`source_ref`, `approval_ref`, `created_at`, `updated_at`,
`compatibility_target`, `replaced_by`) and every unset `PolicyBundleScope`
selector is stored as `None`, the governed, required round-trip
convention for this model — identical to `rule.py`'s, applied
recursively through nested `PolicyBundleScope` and each nested
`OperationAwarePolicyRule` — is:

    dumped = bundle.model_dump(mode="json", exclude_none=True)
    restored = PolicyBundle.model_validate(dumped)
    assert restored == bundle

`exclude_none=True` is a `model_dump` call-time option (not a custom
serializer or custom encoder); pydantic applies it recursively to every
nested `BaseModel`, so nested `OperationAwarePolicyRule`/
`OperationAwarePolicyMatch`/`PolicyCondition` fields are governed by this
same call, not a second, separate one. No custom serializer or encoder is
defined anywhere in this module.

Import boundary
────────────────
This module depends on the standard library, `pydantic`, and
`basis_core.policy.operation_aware.rule.OperationAwarePolicyRule` (PR 13,
reused, not duplicated) only. Like `rule.py`, it reproduces (rather than
imports) the vendored contract's `action_pattern`/`resource_type_pattern`/
`open_identifier_pattern` locally — `policy-bundle.yaml` itself documents
these as "Reproduced from policy-rule.yaml ... so scope validation stays
exactly aligned with rule match validation", the same reproduction
convention `rule.py`'s own docstring documents and justifies (`docs/
import-boundaries.md`: `policy/` may import only from `domain/`, never
from `decisions/`). This module does not import `basis_core.decisions`,
`basis_core.enforcement`, `basis_core.audit`, `basis_core.adapters`,
`basis_core.policy.engine`, or `basis_core.policy.rules`. It does not
import `OperationAwareDecisionRequest` for evaluation, reflection, or
field enumeration of any kind, and does not import
`basis_core.domain.operation_aware_vocabulary` (no field on this model
reuses `ReasonCode`/`RedactionClassification`).

Not implemented by this module (deferred to later, separately-scoped
roadmap PRs): the explicit `PolicyBundleValidationError` structural/
semantic pipeline and duplicate-`rule_id` rejection (PR 15), canonical
compatibility-vector bundle conformance (PR 16), the `scope`-to-request
applicability function (PR 17), policy-owned effect aggregation and
final-outcome semantics (`aggregation.py`, PR 27), and the future
evaluation-owned orchestrator, `OperationAwareEvaluationEngine` (PR 27B).

Public API status: internal to the operation-aware package for now,
exactly like `condition.py` (PR 12) and `rule.py` (PR 13). Not re-exported
from `basis_core.policy` or any other package `__init__.py`; see
`docs/public-api.md`'s "Open API questions" convention and Section 6 of
the roadmap plan for when operation-aware symbols are expected to
graduate to the stable public API (Milestone 11, PR 35).
"""

from __future__ import annotations

import re
from datetime import datetime

from pydantic import BaseModel, ConfigDict, StrictBool, field_validator, model_validator

from basis_core.policy.operation_aware.rule import OperationAwarePolicyRule

# ── Reproduced patterns ─────────────────────────────────────────────────
#
# Reproduced verbatim from the vendored `policy-bundle` contract's own
# `action_pattern` / `resource_type_pattern` / `open_identifier_pattern`
# (themselves reproduced, per the contract's own comment, from
# `policy-rule.yaml`'s byte-identical copies — see this module's
# docstring, "Import boundary", for why this module reproduces rather
# than imports them). `resource_type_pattern` and `open_identifier_pattern`
# are byte-identical strings in the vendored contract, so one compiled
# pattern (`_OPEN_IDENTIFIER_RE`) serves both, exactly as in `rule.py`.

_ACTION_RE = re.compile(r"^[a-z][a-z0-9_-]*:[a-z][a-z0-9_-]*(:[a-z][a-z0-9_-]*)?$")
_OPEN_IDENTIFIER_RE = re.compile(r"^[a-z][a-z0-9_-]*$")
_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


def _require_non_empty(value: str, *, field_name: str) -> str:
    """Shared non-empty/non-whitespace-only check, matching the convention
    already established by `condition.py` and `rule.py`'s own
    `_require_non_empty` helpers (not imported — each operation-aware
    module reproduces this small helper locally; see `rule.py`'s
    docstring, "Import boundary")."""
    if not value.strip():
        raise ValueError(f"{field_name} must not be empty or whitespace-only.")
    return value


# ── Scope shape ───────────────────────────────────────────────────────────
#
# Structured applicability selectors, per `policy-bundle.yaml`'s
# `scope_shape` (ADR-0004 §3). Field groupings mirror `rule.py`'s own
# `_NON_EMPTY_ONLY_FIELDS` / `_PATTERN_FIELDS` split:
#   - `_SCOPE_NON_EMPTY_ONLY_FIELDS`: free-form identifier arrays with no
#     published character-set pattern beyond non-empty/non-whitespace.
#   - `_SCOPE_PATTERN_FIELDS`: arrays validated against one of the two
#     reproduced patterns above.
_SCOPE_NON_EMPTY_ONLY_FIELDS: tuple[str, ...] = (
    "site_ids",
    "building_ids",
    "zone_ids",
    "area_ids",
)

_SCOPE_PATTERN_FIELDS: dict[str, re.Pattern[str]] = {
    "actions": _ACTION_RE,
    "resource_types": _OPEN_IDENTIFIER_RE,
    "device_classes": _OPEN_IDENTIFIER_RE,
    "environment_modes": _OPEN_IDENTIFIER_RE,
    "authority_modes": _OPEN_IDENTIFIER_RE,
    "protocols": _OPEN_IDENTIFIER_RE,
}

# Every published scope selector category, in `scope_shape.optional`'s
# exact order — used for field declaration order below, the explicit-null
# rejection validator, the empty-array rejection validator, and the
# at-least-one-populated-selector check.
_ALL_SCOPE_SELECTOR_FIELDS: tuple[str, ...] = (
    "actions",
    "resource_types",
    "site_ids",
    "building_ids",
    "zone_ids",
    "area_ids",
    "device_classes",
    "environment_modes",
    "authority_modes",
    "protocols",
)


class PolicyBundleScope(BaseModel):
    """
    The structured `scope` object nested on `PolicyBundle` —
    `policy-bundle.yaml`'s `scope_shape`: ten independently-optional
    selector categories restricting a bundle's applicability.

    Every field defaults to `None` — a purely internal sentinel meaning
    "this selector category imposes no restriction". `None` is never a
    legal *explicit* wire value for a selector: a key present with value
    `null` is rejected exactly like a key present with value `[]` — only
    a genuinely *omitted* key defaults to `None`. See this module's
    docstring, "Selector representation", for why (`scope_shape` publishes
    `type: array` only for every selector field, with no `"null"`
    variant — the same pattern `OperationAwarePolicyMatch`'s `match_shape`
    already establishes in `rule.py`).

    An entirely empty scope object (every selector omitted) is itself
    invalid (`policy-bundle.yaml` `constraints`: "must contain at least
    one populated selector; an entirely empty scope object, `{}`, is
    invalid — use omission of the scope field instead"). Callers that want
    "globally applicable, no scope restriction" must omit the `scope`
    field entirely (or pass explicit `None`) on `PolicyBundle`, not
    construct `PolicyBundleScope()`.

    Selector categories and their published constraints:
      site_ids, building_ids, zone_ids, area_ids
          Free-form identifier arrays: non-empty, non-whitespace strings,
          no published character-set pattern.
      resource_types, device_classes, environment_modes, authority_modes,
      protocols
          Open, lowercase, deployment-defined label arrays, validated
          against `open_identifier_pattern` (`^[a-z][a-z0-9_-]*$`).
      actions
          Composite action arrays, validated against `action_pattern`
          (`^[a-z][a-z0-9_-]*:[a-z][a-z0-9_-]*(:[a-z][a-z0-9_-]*)?$`).

    This class performs no applicability determination of any kind: no
    `matches_request()`, no `is_applicable()`, no request-field lookup,
    no hierarchy/prefix/wildcard matching — see this module's docstring,
    "Scope semantics boundary". PR 17 owns applicability.

    Serialization: governed by `PolicyBundle`'s own `model_dump(mode=
    "json", exclude_none=True)` convention (recursive) — see this
    module's docstring, "Governed serialization convention". Every
    unpopulated selector is stored as `None` and therefore omitted
    entirely from that dump; every populated selector is emitted as its
    (always non-empty) array. No custom serializer or encoder is used or
    required.
    """

    actions: list[str] | None = None
    resource_types: list[str] | None = None
    site_ids: list[str] | None = None
    building_ids: list[str] | None = None
    zone_ids: list[str] | None = None
    area_ids: list[str] | None = None
    device_classes: list[str] | None = None
    environment_modes: list[str] | None = None
    authority_modes: list[str] | None = None
    protocols: list[str] | None = None

    model_config = ConfigDict(frozen=True, extra="forbid")

    @model_validator(mode="before")
    @classmethod
    def _reject_explicit_null_selectors(cls, data: object) -> object:
        """Reject an explicit `null` for any of the ten selector fields,
        while still allowing a genuinely omitted key to fall through to
        the field's own `None` default. See `rule.py`'s
        `OperationAwarePolicyMatch._reject_explicit_null_selectors` for
        the full rationale this reproduces unchanged for `scope_shape`."""
        if isinstance(data, dict):
            explicit_null_fields = sorted(
                field_name
                for field_name in _ALL_SCOPE_SELECTOR_FIELDS
                if field_name in data and data[field_name] is None
            )
            if explicit_null_fields:
                raise ValueError(
                    "PolicyBundleScope does not accept an explicit null for a selector "
                    f"field; found explicit null for: {explicit_null_fields}. The vendored "
                    "contract types each selector as `array` only (no `null` variant) — "
                    "omit the field entirely to signal 'no restriction'."
                )
        return data

    @field_validator(*_ALL_SCOPE_SELECTOR_FIELDS, mode="after")
    @classmethod
    def _reject_explicit_empty_array(cls, v: list[str] | None, info: object) -> list[str] | None:
        if v is None:
            return v
        field_name = info.field_name  # type: ignore[attr-defined]
        if len(v) == 0:
            raise ValueError(
                f"PolicyBundleScope.{field_name} must be a non-empty array when present; "
                "an explicitly empty selector array is invalid. Omit the field entirely "
                "to signal 'no restriction' (an explicit null is also rejected)."
            )
        return v

    @field_validator(*_SCOPE_NON_EMPTY_ONLY_FIELDS, mode="after")
    @classmethod
    def _check_non_empty_items(cls, v: list[str] | None, info: object) -> list[str] | None:
        if v is None:
            return v
        field_name = info.field_name  # type: ignore[attr-defined]
        for item in v:
            _require_non_empty(item, field_name=f"PolicyBundleScope.{field_name} item")
        return v

    @field_validator(*_SCOPE_PATTERN_FIELDS.keys(), mode="after")
    @classmethod
    def _check_pattern_items(cls, v: list[str] | None, info: object) -> list[str] | None:
        if v is None:
            return v
        field_name = info.field_name  # type: ignore[attr-defined]
        pattern = _SCOPE_PATTERN_FIELDS[field_name]
        for item in v:
            if not pattern.match(item):
                raise ValueError(
                    f"PolicyBundleScope.{field_name} item {item!r} does not match the "
                    f"required pattern {pattern.pattern!r}."
                )
        return v

    @model_validator(mode="after")
    def _check_at_least_one_populated_selector(self) -> PolicyBundleScope:
        if not any(getattr(self, field_name) for field_name in _ALL_SCOPE_SELECTOR_FIELDS):
            raise ValueError(
                "PolicyBundleScope must contain at least one populated selector; an "
                "entirely empty scope object ({}) is invalid. Omit the `scope` field "
                "entirely (or supply null) to signal 'globally applicable'."
            )
        return self


class PolicyBundle(BaseModel):
    """
    The unit of policy identity, versioning, scope, ownership, provenance,
    and rule grouping — the shape published by `basis-schemas` v0.2.0's
    `policy-bundle` contract (ADR-0004 §2-3).

    A bundle is inert data: this type performs no evaluation of any kind
    — no `evaluate()`, no bundle selection, no applicability
    determination, no rule matching, no condition evaluation, no deny
    precedence, and no loading/storage/distribution/signing behavior. See
    this module's docstring for the full boundary.

    Required fields
    ────────────────
    bundle_id       Stable, machine-readable identifier for this bundle,
                     independent of any local filename or repository path.
                     Non-empty; no character-set pattern beyond that —
                     never inferred from `rule_id`/`condition_id`/
                     `request_id` grammar, never trimmed, lowercased,
                     rewritten, or generated.
    bundle_version  This bundle's own authored-content version
                     (`MAJOR.MINOR.PATCH`). Distinct from `schema_version`
                     and from the installed `basis-schemas` package
                     version. Preserved exactly as supplied — no semantic-
                     version parsing, comparison, upgrade/downgrade logic,
                     or version negotiation is implemented.
    schema_version  The version of the `policy-bundle` contract SHAPE this
                     instance was authored against (`MAJOR.MINOR.PATCH`).
                     Distinct from `bundle_version` and from the installed
                     `basis-schemas` package version. Not compared against
                     the runtime's supported version — schema
                     compatibility evaluation is later roadmap work.
    policy_owner    Stable, opaque reference to who authored or is
                     accountable for this bundle's content. Provenance and
                     governance metadata only — NOT an authorization
                     subject, grants no permission by its presence, is
                     never resolved through `basis-identity`, and is never
                     used to authorize anything.
    rules           Non-empty `list[OperationAwarePolicyRule]` (PR 13,
                     reused directly, nested dict values reconstruct as
                     strongly-typed rules). Order is preserved; never
                     sorted, deduplicated, or treated as evaluation-
                     significant. Duplicate `rule_id` values across this
                     array are NOT rejected here — see this module's
                     docstring, "Deferred to PR 15".

    Optional fields
    ────────────────
    scope                 Structured applicability scope
                           (`PolicyBundleScope`). Defaults to `None` —
                           absence (or explicit `null`) means globally
                           applicable. This module implements no
                           applicability determination of any kind; see
                           "Scope semantics boundary" above.
    description            Optional, non-empty-when-present human-readable
                           summary. Static author text only — never
                           interpolated, formatted, derived, or treated as
                           authoritative evidence.
    source_ref             Optional, non-empty-when-present provenance
                           reference. Never fetched, opened, or verified
                           to exist.
    approval_ref           Optional, non-empty-when-present reference to an
                           external approval/review record. Never used to
                           verify approval, resolve an approver, or imply
                           the bundle is approved.
    created_at/updated_at  Optional, timezone-aware timestamps. Naive
                           datetimes are rejected. Never populated from the
                           runtime clock; never compared to each other.
    compatibility_target   Optional, non-empty-when-present declarative
                           label. No compatibility resolution or
                           enforcement is implemented against its value.
    deprecated             Strict `bool`, defaults to `False`. Lifecycle
                           metadata only — deprecation does not disable
                           evaluation in this module (there is no
                           evaluation here to disable).
    replaced_by             Optional, non-empty-when-present `bundle_id`
                           reference to a replacement bundle. Never
                           resolved, loaded, or checked for existence. The
                           vendored contract explicitly does not require
                           `replaced_by` only when `deprecated` is `true`
                           ("producers are expected to keep the two fields
                           logically consistent, but that alignment is not
                           implemented here") — this module therefore
                           implements no cross-field invariant between the
                           two, exactly as published.

    No `validation_status` field exists on this model, and one cannot be
    supplied — `extra="forbid"` rejects it (along with any other unknown
    field) as an unrecognized key. See this module's docstring.

    Serialization: the governed round-trip convention is
    `model_dump(mode="json", exclude_none=True)` — see this module's
    docstring, "Governed serialization convention". No custom serializer
    or custom encoder is used or required.
    """

    bundle_id: str
    bundle_version: str
    schema_version: str
    policy_owner: str
    scope: PolicyBundleScope | None = None
    rules: list[OperationAwarePolicyRule]
    description: str | None = None
    source_ref: str | None = None
    approval_ref: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    compatibility_target: str | None = None
    deprecated: StrictBool = False
    replaced_by: str | None = None

    model_config = ConfigDict(frozen=True, extra="forbid")

    @field_validator("bundle_id", mode="after")
    @classmethod
    def _bundle_id_must_not_be_empty(cls, v: str) -> str:
        return _require_non_empty(v, field_name="PolicyBundle.bundle_id")

    @field_validator("policy_owner", mode="after")
    @classmethod
    def _policy_owner_must_not_be_empty(cls, v: str) -> str:
        return _require_non_empty(v, field_name="PolicyBundle.policy_owner")

    @field_validator("bundle_version", mode="after")
    @classmethod
    def _bundle_version_must_be_well_formed(cls, v: str) -> str:
        v = _require_non_empty(v, field_name="PolicyBundle.bundle_version")
        if not _SEMVER_RE.match(v):
            raise ValueError(
                f"PolicyBundle.bundle_version {v!r} does not match the required "
                r"MAJOR.MINOR.PATCH pattern '^\d+\.\d+\.\d+$'. bundle_version is this "
                "bundle's own content version — distinct from schema_version — and is "
                "preserved verbatim, never parsed for ordering or compared."
            )
        return v

    @field_validator("schema_version", mode="after")
    @classmethod
    def _schema_version_must_be_well_formed(cls, v: str) -> str:
        v = _require_non_empty(v, field_name="PolicyBundle.schema_version")
        if not _SEMVER_RE.match(v):
            raise ValueError(
                f"PolicyBundle.schema_version {v!r} does not match the required "
                r"MAJOR.MINOR.PATCH pattern '^\d+\.\d+\.\d+$'. schema_version identifies "
                "the policy-bundle contract SHAPE this instance was authored against — "
                "distinct from bundle_version — and is not compared against the "
                "installed basis-schemas package version by this module."
            )
        return v

    @field_validator("rules", mode="after")
    @classmethod
    def _rules_must_be_non_empty(
        cls, v: list[OperationAwarePolicyRule]
    ) -> list[OperationAwarePolicyRule]:
        if len(v) == 0:
            raise ValueError(
                "PolicyBundle.rules must be a non-empty array; a bundle with zero rules "
                "cannot produce a substantive decision."
            )
        return v

    @field_validator(
        "description",
        "source_ref",
        "approval_ref",
        "compatibility_target",
        "replaced_by",
        mode="after",
    )
    @classmethod
    def _optional_provenance_fields_must_not_be_empty_if_present(
        cls, v: str | None, info: object
    ) -> str | None:
        if v is None:
            return v
        field_name = info.field_name  # type: ignore[attr-defined]
        return _require_non_empty(v, field_name=f"PolicyBundle.{field_name}")

    @field_validator("created_at", "updated_at", mode="after")
    @classmethod
    def _timestamps_must_be_tz_aware(cls, v: datetime | None, info: object) -> datetime | None:
        if v is None:
            return v
        if v.tzinfo is None:
            field_name = info.field_name  # type: ignore[attr-defined]
            raise ValueError(
                f"PolicyBundle.{field_name} must be timezone-aware when provided (e.g. "
                "'2026-05-22T14:30:00Z' or '2026-05-22T14:30:00-06:00'). No system-clock "
                "default is applied by this model."
            )
        return v
