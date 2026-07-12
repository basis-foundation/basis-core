"""
basis_core.policy.operation_aware.rule — the `OperationAwarePolicyRule`
data model.

This module is the second module added under `src/basis_core/policy/
operation_aware/` for `basis-core` v0.2.0 (see
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`, Milestone 4,
PR 13 — "OperationAwarePolicyRule model"), after PR 12's `condition.py`. It
implements exactly the shape published by `basis-schemas` v0.2.0's
`policy-rule` contract (ADR-0004 §4-5):

  OperationAwarePolicyRule   A single, inert, data-only unit of
                              authorization evaluation: a stable rule
                              identifier, a closed allow/deny effect,
                              explicit operation-aware match criteria
                              (`OperationAwarePolicyMatch`), zero or more
                              `PolicyCondition` (PR 12, reused directly),
                              an optional reason code (reusing the
                              `ReasonCode` vocabulary type unchanged), and
                              an optional static, non-executable
                              explanation.
  OperationAwarePolicyMatch  The structured, closed-shape nested match
                              object: twenty independently-optional
                              selector categories mirroring
                              `operation-aware-decision-request`'s own
                              categories (contract's own "a rule can only
                              match what a request can carry"
                              observation). Every populated selector is a
                              non-empty array of alternatives (any-of);
                              an entirely empty match object is invalid.
  RuleEffect                 Closed, two-value vocabulary (`allow` /
                              `deny`) for a rule's `effect` field.
                              `not_applicable` is deliberately excluded —
                              it is a bundle-applicability outcome, never
                              a rule effect (see the vendored contract's
                              file header and ADR-0004 Section 5).

Naming — deliberate collision avoidance with the v0.1.0 `PolicyRule`
Protocol
────────────────────────────────────────────────────────────────────────
`basis_core.policy.engine.PolicyRule` is a v0.1.0 `Protocol` (a code
*interface*), already re-exported from `basis_core.policy`. This module's
`OperationAwarePolicyRule` is an unrelated v0.2.0 *data model* (a Pydantic
`BaseModel`) — same-shaped name, different concept, different package
layer. To avoid any possibility of import confusion, this module is named
`OperationAwarePolicyRule`, is never imported into `basis_core.policy`'s
`__init__.py`, and `from basis_core.policy import PolicyRule` continues to
resolve to the existing v0.1.0 `Protocol` unchanged — see
`tests/operation_aware/test_policy_rule.py`'s
`TestNamingCollisionRegression` for the mandatory, mechanically-checked
proof.

Architectural boundary — structural shape only, no evaluation
────────────────────────────────────────────────────────────────────────
This module publishes the rule *shape*. It does not implement, and must
never grow:
  - rule matching (`matches()`, `evaluate()`, selector dispatch, or any
    other request-field lookup against `match`'s selectors)
  - condition evaluation (that remains `PolicyCondition`'s own documented
    boundary — see `condition.py`)
  - deny precedence, default-deny, or any other rule-combining semantics
  - bundle-level behavior (bundle `rule_id` uniqueness, bundle scope,
    bundle applicability) — that is `PolicyBundle`, later roadmap work
    (PR 14)
  - rule ordering or priority — the vendored contract deliberately
    publishes no such field (see the vendored contract's file header);
    `rule_id` is a stable identifier only, never an ordering signal

This module implements two rule-owned structural invariants the vendored
contract assigns to the rule's own schema (not to a future bundle-level
validator):
  - at least one of `match`/`conditions` must be present and non-empty —
    an unconditional rule (matches every request in its bundle's scope)
    is not permitted
  - `condition_id` values must be unique within one rule's `conditions`
    array — a rule-level check because the rule, not any individual
    condition, owns the array being checked for duplicates

Both are expressed as Pydantic validators, not a separately-scoped
exception hierarchy — the explicit `PolicyBundleValidationError`
structural/semantic pipeline is later, separately-scoped roadmap work
(PR 15).

Selector/`conditions` representation: `None` is an internal sentinel only
────────────────────────────────────────────────────────────────────────
Every one of `OperationAwarePolicyMatch`'s twenty selector fields, and
`OperationAwarePolicyRule.conditions`, is typed `... | None = None` rather
than `Field(default_factory=list)`. `None` here is a Python-level, purely
*internal* representation of "this field was not supplied" — never a
value that is itself legal as explicit wire input for a selector field
(see "Contract basis" below; `conditions` is the one exception, per its
own published `[array, "null"]` type).

The twenty `match_shape` selector fields therefore accept exactly four
distinguishable input states, mechanically enforced:

  key omitted entirely      → accepted; stored internally as `None`
  key present, value `null` → **rejected** (`ValidationError`)
  key present, value `[]`   → **rejected** (`ValidationError`)
  key present, non-empty
    array                   → accepted, item-validated, stored as-is

Distinguishing "key omitted" from "key present with value `None`" is not
possible from inside an ordinary field validator — by the time a field
validator runs, both cases have already collapsed to the same Python
`None`. `OperationAwarePolicyMatch._reject_explicit_null_selectors`
(`model_validator(mode="before")`) is what makes the distinction: it
inspects the *raw* input mapping, before any field defaulting happens,
and rejects only a selector key that is actually present with a `None`/
`null` value. A genuinely omitted key never reaches this check at all and
falls through to the field's own `None` default undisturbed.

Contract basis (vendored `policy-rule.yaml`, re-inspected for this
revision; no companion `.md` document exists in the vendored snapshot)
────────────────────────────────────────────────────────────────────────
  - The twenty `match_shape` selector fields (`subject_ids` ...
    `risk_classifications`): each field's published `type` is `array`
    only — no `"null"` variant is declared anywhere in `match_shape`,
    unlike `match`/`conditions`/`reason_code`/`explanation`, which each
    explicitly publish `[type, "null"]`. No vendored valid or invalid
    example exercises an explicit `null` for any selector either way.
    Because the contract does not publish `null` as a legal selector
    value, this module does not accept it — accepting an undocumented
    value would broaden the contract, not merely fill a gap.
    `match_semantics.empty_selector_list: invalid` (plus explicit
    constraint prose and a vendored *invalid* fixture example,
    `match: {actions: []}`) separately and unconditionally forbids an
    explicit empty array.
  - `conditions` (rule-level) is different: its own field `type` is
    `[array, "null"]`. Explicit `null` is a *published, first-class*
    legal value for this field — not an inference made by this module —
    so `conditions` continues to accept explicit `null` (treated
    identically to omission), unaffected by the selector-level
    restriction above.
  - No vendored valid example ever serializes an unpopulated selector as
    `[]` or `null` — every valid example simply omits the key. Omission is
    the only wire representation the contract's own examples demonstrate
    for "this selector is not part of the rule".

Governed serialization convention: `exclude_none=True`
────────────────────────────────────────────────────────────────────────
Because every unset selector/`conditions`/`match`/`reason_code`/
`explanation` field is stored as `None`, and because a plain
`model_dump(mode="json")` therefore emits `null` for each of them, the
required, governed round-trip convention for this model is:

    dumped = rule.model_dump(mode="json", exclude_none=True)
    restored = OperationAwarePolicyRule.model_validate(dumped)
    assert restored == rule

`exclude_none=True` is a `model_dump` call-time option (not a custom
serializer or custom encoder) that omits every `None`-valued field —
recursively, including `OperationAwarePolicyMatch`'s nested
selectors — from the dumped mapping. The resulting JSON therefore
contains, for every rule, only non-empty selector arrays and populated
top-level fields: never an empty array, and never an explicit `null` —
matching the wire shape every vendored valid example itself demonstrates
(see "Contract basis" above). Reconstructing via `model_validate` on that
leaner mapping always yields an equal object, because every omitted key
falls back to the same `None` default the original rule already held.

Import boundary
────────────────
This module depends on the standard library, `pydantic`,
`basis_core.policy.operation_aware.condition.PolicyCondition` (PR 12,
reused, not duplicated), and
`basis_core.domain.operation_aware_vocabulary.ReasonCode` (reused,
not duplicated). It does not import `basis_core.policy.engine`,
`basis_core.policy.rules`, `basis_core.enforcement`, `basis_core.audit`,
or `basis_core.adapters`.

It also does not import anything from `basis_core.decisions` — even
though the vendored contract's `action_pattern`/`resource_pattern`/
`resource_type_pattern`/`open_identifier_pattern`/`operation_intent_values`
are byte-identical to the ones `basis_core.decisions.models` and
`basis_core.decisions.operation_aware` already compile and enforce for
`DecisionRequest`/`OperationAwareDecisionRequest`, `docs/import-
boundaries.md` states as a hard architectural rule that `policy/` may
import only from `domain/` and must not import from `decisions/` (this is
stronger than, and takes precedence over, the general "reuse an existing
compiled validator when safe to import" guidance — see this module's
final PR report for the explicit note on this tension). Consistent with
the vendored contract's own "Reproduced patterns / value sets" section
(policy-rule.yaml: "Reproduced verbatim from the dependency contracts ...
so a consumer can validate a rule without dereferencing them"), and with
this repository's existing precedent of intentionally duplicating simple,
stable patterns per-module (`decisions/operation_aware.py`'s own
docstring, `domain/evidence.py`'s `_PROTOCOL_RE`) rather than creating a
shared-pattern import, this module reproduces those five pattern/value-set
definitions locally instead.

It does not import `OperationAwareDecisionRequest` for evaluation,
reflection, or field enumeration of any kind.

Not implemented by this module (deferred to later, separately-scoped
roadmap PRs): `PolicyBundle` (PR 14), the explicit
`PolicyBundleValidationError` structural/semantic pipeline (PR 15), match
selector evaluation (PR 19), condition evaluation (PR 22-23), and the
`OperationAwarePolicyEngine` (PR 27).

Public API status: internal to the operation-aware package for now,
exactly like `condition.py` (PR 12). Not re-exported from
`basis_core.policy` or any other package `__init__.py`; see
`docs/public-api.md`'s "Open API questions" convention and Section 6 of
the roadmap plan for when operation-aware symbols are expected to graduate
to the stable public API (Milestone 11, PR 35).
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    PlainSerializer,
    PlainValidator,
    field_validator,
    model_validator,
)

from basis_core.domain.operation_aware_vocabulary import ReasonCode
from basis_core.policy.operation_aware.condition import PolicyCondition

# ── Reproduced patterns / value sets ────────────────────────────────────
#
# Reproduced verbatim from the vendored `policy-rule` contract's own
# `action_pattern` / `resource_pattern` / `resource_type_pattern` /
# `open_identifier_pattern` / `operation_intent_values` (themselves
# byte-identical reproductions of `operation-aware-decision-request`'s
# copies — see this module's docstring, "Import boundary", for why this
# module reproduces rather than imports them). `resource_type_pattern` and
# `open_identifier_pattern` are byte-identical strings in the vendored
# contract, so one compiled pattern (`_OPEN_IDENTIFIER_RE`) serves both.

_ACTION_RE = re.compile(r"^[a-z][a-z0-9_-]*:[a-z][a-z0-9_-]*(:[a-z][a-z0-9_-]*)?$")
_RESOURCE_RE = re.compile(r"^[a-z][a-z0-9_-]*:[a-z0-9][a-z0-9_-]*$")
_OPEN_IDENTIFIER_RE = re.compile(r"^[a-z][a-z0-9_-]*$")

# `match.operation_intents` items must each be one of
# operation-aware-decision-request's closed `operation_intent` vocabulary,
# reproduced verbatim here (see policy-rule.yaml's `operation_intent_values`)
# as a `Literal` rather than a duplicate `Enum` class — no evaluation or
# identity beyond structural validation is needed for this closed set.
_OperationIntentValue = Literal["read_only", "state_changing", "control_affecting"]


def _require_non_empty(value: str, *, field_name: str) -> str:
    """Shared non-empty/non-whitespace-only check, matching the convention
    already established by `condition.py`'s `_require_non_empty` and
    `decisions/operation_aware.py`'s `_require_non_empty`/
    `_require_non_empty_if_present` (not imported — see this module's
    "Import boundary" docstring section)."""
    if not value.strip():
        raise ValueError(f"{field_name} must not be empty or whitespace-only.")
    return value


# ── reason_code: reuse `ReasonCode` structurally, without requiring
#    `arbitrary_types_allowed` ─────────────────────────────────────────
#
# `ReasonCode` (domain/operation_aware_vocabulary.py) is a plain `str`
# subclass with validation in `__new__`, not a Pydantic-native type. Rather
# than duplicate its regex here or force
# `model_config = ConfigDict(arbitrary_types_allowed=True)` (which would
# also require a custom JSON serializer), this module wraps it in a
# `PlainValidator`/`PlainSerializer` pair local to this module: input is
# constructed through `ReasonCode.__new__` unchanged (so `ReasonCode`'s own
# validation is the only validation — no duplicated pattern), and output
# serializes back to a plain `str` for `model_dump(mode="json")`.


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


class RuleEffect(str, Enum):
    """
    The closed, two-value rule-effect vocabulary (`policy-rule.yaml`'s
    `effect` field, ADR-0004 Section 5).

    Closed to exactly `allow` / `deny`. `not_applicable` is deliberately
    excluded: it is a bundle-applicability outcome ("no applicable policy
    bundle"), never something an individual rule inside an applicable
    bundle produces — conflating the two would blur the distinction
    ADR-0002 Section 5 exists to preserve. This enum implements no
    combining, precedence, or evaluation semantics of its own; a future
    `OperationAwarePolicyEngine` (PR 27) is the only place deny precedence
    is implemented.
    """

    ALLOW = "allow"
    DENY = "deny"


# ── Match criteria shape ─────────────────────────────────────────────────
#
# Structured selectors mirroring `operation-aware-decision-request`'s own
# categories (policy-rule.yaml `match_shape`; ADR-0004 Section 6: "a rule
# can only match what a request can carry"). Every selector is an array of
# alternatives (any-of *within* one populated selector); every *populated*
# selector category must match for the match object as a whole (all-of
# *across* selectors) — match_semantics below documents, but this module
# does not implement, that future evaluator-level combination.
#
# Field groupings, matching the vendored contract's own field-by-field
# `constraints`:
#   - `_NON_EMPTY_ONLY_FIELDS`: free-form identifier arrays with no
#     published character-set pattern beyond non-empty/non-whitespace.
#   - `_PATTERN_FIELDS`: arrays validated against one of the four
#     reproduced patterns above.
#   - `operation_intents` is handled separately (closed `Literal`, not a
#     free-form pattern).
_NON_EMPTY_ONLY_FIELDS: tuple[str, ...] = (
    "subject_ids",
    "subject_roles",
    "identity_sources",
    "site_ids",
    "building_ids",
    "zone_ids",
    "area_ids",
    "device_ids",
    "protocol_operations",
)

_PATTERN_FIELDS: dict[str, re.Pattern[str]] = {
    "authority_modes": _OPEN_IDENTIFIER_RE,
    "actions": _ACTION_RE,
    "resources": _RESOURCE_RE,
    "resource_types": _OPEN_IDENTIFIER_RE,
    "device_classes": _OPEN_IDENTIFIER_RE,
    "protocols": _OPEN_IDENTIFIER_RE,
    "safety_modes": _OPEN_IDENTIFIER_RE,
    "safety_classifications": _OPEN_IDENTIFIER_RE,
    "environment_modes": _OPEN_IDENTIFIER_RE,
    "risk_classifications": _OPEN_IDENTIFIER_RE,
}

# Every published selector category, in `match_shape.optional`'s exact
# order — used both for field declaration order below, for the
# empty-array rejection validator, and for the at-least-one-populated-
# selector check.
_ALL_SELECTOR_FIELDS: tuple[str, ...] = (
    "subject_ids",
    "subject_roles",
    "identity_sources",
    "authority_modes",
    "actions",
    "resources",
    "resource_types",
    "site_ids",
    "building_ids",
    "zone_ids",
    "area_ids",
    "device_ids",
    "device_classes",
    "protocols",
    "protocol_operations",
    "operation_intents",
    "safety_modes",
    "safety_classifications",
    "environment_modes",
    "risk_classifications",
)


class OperationAwarePolicyMatch(BaseModel):
    """
    The structured `match` object nested on `OperationAwarePolicyRule` —
    twenty independently-optional selector categories
    (`policy-rule.yaml`'s `match_shape`).

    Every field defaults to `None` — a purely internal sentinel meaning
    "this selector category imposes no restriction"
    (`match_semantics.absent_selector: no_restriction`). `None` is never a
    legal *explicit* wire value for a selector: a key that is present with
    value `null` is rejected exactly like a key present with value `[]`
    (`match_semantics.empty_selector_list: invalid`) — only a genuinely
    *omitted* key defaults to `None`. See this module's docstring,
    "Contract basis", and `_reject_explicit_null_selectors` below for how
    "omitted" and "present but null" are distinguished. Within one
    populated selector, listed values are alternatives (any-of); this
    class does not implement, and never will implement, how selectors
    combine with each other or against a real request (see this module's
    docstring).

    An entirely empty match object (every selector omitted) is itself
    invalid — see `_check_at_least_one_populated_selector` below. Callers
    that want "no match-based restriction, relying on `conditions` alone"
    must omit the `match` field entirely (`match=None`), not construct
    `OperationAwarePolicyMatch()`.

    Selector categories and their published constraints:
      subject_ids, subject_roles, identity_sources, site_ids,
      building_ids, zone_ids, area_ids, device_ids, protocol_operations
          Free-form identifier arrays: non-empty, non-whitespace strings,
          no published character-set pattern.
      authority_modes, resource_types, device_classes, protocols,
      safety_modes, safety_classifications, environment_modes,
      risk_classifications
          Open, lowercase, deployment-defined label arrays, validated
          against `open_identifier_pattern`
          (`^[a-z][a-z0-9_-]*$`).
      actions
          Composite action arrays, validated against `action_pattern`
          (`^[a-z][a-z0-9_-]*:[a-z][a-z0-9_-]*(:[a-z][a-z0-9_-]*)?$`).
      resources
          Canonical resource-identifier arrays, validated against
          `resource_pattern`
          (`^[a-z][a-z0-9_-]*:[a-z0-9][a-z0-9_-]*$`).
      operation_intents
          Closed to `read_only` / `state_changing` / `control_affecting`.

    This class performs no evaluation: no `matches()`, no request-field
    lookup, no selector dispatch.

    Serialization: the governed round-trip convention is
    `model_dump(mode="json", exclude_none=True)` — see this module's
    docstring, "Governed serialization convention". Every unpopulated
    selector is stored as `None` and is therefore omitted entirely from
    that dump (never emitted as `[]` or as an explicit `null`); every
    populated selector is emitted as its (always non-empty) array. No
    custom serializer or custom encoder is used or required.
    """

    subject_ids: list[str] | None = None
    subject_roles: list[str] | None = None
    identity_sources: list[str] | None = None
    authority_modes: list[str] | None = None
    actions: list[str] | None = None
    resources: list[str] | None = None
    resource_types: list[str] | None = None
    site_ids: list[str] | None = None
    building_ids: list[str] | None = None
    zone_ids: list[str] | None = None
    area_ids: list[str] | None = None
    device_ids: list[str] | None = None
    device_classes: list[str] | None = None
    protocols: list[str] | None = None
    protocol_operations: list[str] | None = None
    operation_intents: list[_OperationIntentValue] | None = None
    safety_modes: list[str] | None = None
    safety_classifications: list[str] | None = None
    environment_modes: list[str] | None = None
    risk_classifications: list[str] | None = None

    model_config = ConfigDict(frozen=True, extra="forbid")

    @model_validator(mode="before")
    @classmethod
    def _reject_explicit_null_selectors(cls, data: object) -> object:
        """Reject an explicit `null` for any of the twenty selector
        fields, while still allowing a genuinely omitted key to fall
        through to the field's own `None` default.

        This distinction cannot be made inside an ordinary (per-field)
        validator: by the time a field validator runs, "key omitted" and
        "key present with value `None`" have already collapsed to the
        same Python `None` — there is no way, from inside the field
        validator alone, to tell them apart. Inspecting the *raw* input
        mapping here, before pydantic resolves field defaults, is what
        makes the distinction possible: only a selector key that is
        actually present in `data` with value `None` is rejected; an
        absent key is untouched and reaches the field's own default
        exactly as before.

        See this module's docstring, "Contract basis", for why an
        explicit selector `null` is out-of-contract: `match_shape`
        publishes `type: array` only for every selector field, with no
        `"null"` variant (unlike `match`/`conditions`/`reason_code`/
        `explanation`, which each explicitly publish `[type, "null"]`).
        `conditions` is handled separately, at the rule level, and is not
        affected by this check.
        """
        if isinstance(data, dict):
            explicit_null_fields = sorted(
                field_name
                for field_name in _ALL_SELECTOR_FIELDS
                if field_name in data and data[field_name] is None
            )
            if explicit_null_fields:
                raise ValueError(
                    "OperationAwarePolicyMatch does not accept an explicit null for a "
                    f"selector field; found explicit null for: {explicit_null_fields}. The "
                    "vendored contract types each selector as `array` only (no `null` "
                    "variant) — omit the field entirely to signal 'no restriction'."
                )
        return data

    @field_validator(*_ALL_SELECTOR_FIELDS, mode="after")
    @classmethod
    def _reject_explicit_empty_array(cls, v: list[str] | None, info: object) -> list[str] | None:
        if v is None:
            return v
        field_name = info.field_name  # type: ignore[attr-defined]
        if len(v) == 0:
            raise ValueError(
                f"OperationAwarePolicyMatch.{field_name} must be a non-empty array when "
                "present; an explicitly empty selector array is invalid. Omit the field "
                "entirely to signal 'no restriction' (an explicit null is also rejected — "
                "see `_reject_explicit_null_selectors`)."
            )
        return v

    @field_validator(*_NON_EMPTY_ONLY_FIELDS, mode="after")
    @classmethod
    def _check_non_empty_items(cls, v: list[str] | None, info: object) -> list[str] | None:
        if v is None:
            return v
        field_name = info.field_name  # type: ignore[attr-defined]
        for item in v:
            _require_non_empty(item, field_name=f"OperationAwarePolicyMatch.{field_name} item")
        return v

    @field_validator(*_PATTERN_FIELDS.keys(), mode="after")
    @classmethod
    def _check_pattern_items(cls, v: list[str] | None, info: object) -> list[str] | None:
        if v is None:
            return v
        field_name = info.field_name  # type: ignore[attr-defined]
        pattern = _PATTERN_FIELDS[field_name]
        for item in v:
            if not pattern.match(item):
                raise ValueError(
                    f"OperationAwarePolicyMatch.{field_name} item {item!r} does not match "
                    f"the required pattern {pattern.pattern!r}."
                )
        return v

    @model_validator(mode="after")
    def _check_at_least_one_populated_selector(self) -> OperationAwarePolicyMatch:
        if not any(getattr(self, field_name) for field_name in _ALL_SELECTOR_FIELDS):
            raise ValueError(
                "OperationAwarePolicyMatch must contain at least one populated selector; "
                "an entirely empty match object ({}) is invalid. Omit the `match` field "
                "entirely to signal 'no match-based restriction'."
            )
        return self


class OperationAwarePolicyRule(BaseModel):
    """
    A single, inert, data-only unit of authorization evaluation — the
    shape published by `basis-schemas` v0.2.0's `policy-rule` contract
    (ADR-0004 §4-5).

    Deliberately named `OperationAwarePolicyRule`, not `PolicyRule` — see
    this module's docstring, "Naming — deliberate collision avoidance",
    for why. This type performs no evaluation of any kind: no `evaluate()`,
    no `matches()`, no selector dispatch, no condition dispatch, no deny
    precedence, and no bundle-level behavior.

    Required fields
    ────────────────
    rule_id   Stable identifier for this rule, unique within its
              containing bundle (bundle-level validation — `PolicyBundle`,
              PR 14 — not something this single rule's own type can
              enforce). Non-empty; no character-set pattern beyond that;
              never derived from array position.
    effect    Closed to exactly `allow` / `deny` (`RuleEffect`).

    Optional fields
    ────────────────
    match         Structured match criteria (`OperationAwarePolicyMatch`).
                  Defaults to `None` ("no match-based restriction" —
                  distinct from an empty match object, which is invalid).
    conditions    Zero or more `PolicyCondition` values (PR 12, reused
                  directly). Defaults to `None`, meaning "no conditions" —
                  the vendored contract's own field type is `[array,
                  "null"]`, so an explicit `null` input is also accepted
                  and treated identically to omission (`None` is a
                  published, not inferred, legal representation here; see
                  this module's docstring, "Contract basis"). This is
                  unlike `OperationAwarePolicyMatch`'s selector fields,
                  which reject an explicit `null` — `conditions` publishes
                  its own, distinct `null` allowance. A present-but-empty
                  array (`[]`) is always rejected regardless.
    reason_code   Optional `ReasonCode` (reused, not redefined — see this
                  module's "reason_code" section). Defaults to `None`.
    explanation   Optional static, non-empty, human-readable string.
                  Defaults to `None`. No template, variable-interpolation,
                  expression-evaluation, or script-execution mechanism of
                  any kind — a single opaque string field.

    Validation
    ───────────
    At least one of `match`/`conditions` must be present and non-empty —
    an unconditional rule (matches every request in its bundle's scope) is
    rejected. Because `OperationAwarePolicyMatch` itself already rejects
    an entirely empty match object, and `conditions` can never legitimately
    hold an empty (as opposed to `None`) list, this check only needs to
    confirm `match is not None or bool(conditions)`.

    `condition_id` values must be unique within this rule's `conditions`
    array (rule-level validation — the rule owns the array; a standalone
    `PolicyCondition` has no sibling conditions to compare against, so
    `condition.py` cannot and does not enforce this itself).

    Serialization: the governed round-trip convention is
    `model_dump(mode="json", exclude_none=True)` — see this module's
    docstring, "Governed serialization convention". `match`/`conditions`/
    `reason_code`/`explanation`, and every selector nested under `match`,
    are stored as `None` when unset and are therefore omitted entirely
    from that dump (never emitted as `[]` or as an explicit `null`). No
    custom serializer or custom encoder is used or required.
    """

    rule_id: str
    effect: RuleEffect
    match: OperationAwarePolicyMatch | None = None
    conditions: list[PolicyCondition] | None = None
    reason_code: ReasonCodeField = None
    explanation: str | None = None

    model_config = ConfigDict(frozen=True, extra="forbid")

    @field_validator("rule_id", mode="after")
    @classmethod
    def _rule_id_must_not_be_empty(cls, v: str) -> str:
        return _require_non_empty(v, field_name="OperationAwarePolicyRule.rule_id")

    @field_validator("conditions", mode="after")
    @classmethod
    def _reject_explicit_empty_conditions(
        cls, v: list[PolicyCondition] | None
    ) -> list[PolicyCondition] | None:
        if v is None:
            return v
        if len(v) == 0:
            raise ValueError(
                "OperationAwarePolicyRule.conditions must be a non-empty array when "
                "present; an explicitly empty conditions array is invalid. Omit the "
                "field (or supply null) to signal 'no conditions'."
            )
        return v

    @field_validator("explanation", mode="after")
    @classmethod
    def _explanation_must_not_be_empty_if_present(cls, v: str | None) -> str | None:
        if v is None:
            return v
        return _require_non_empty(v, field_name="OperationAwarePolicyRule.explanation")

    @model_validator(mode="after")
    def _check_at_least_one_of_match_or_conditions(self) -> OperationAwarePolicyRule:
        if self.match is None and not self.conditions:
            raise ValueError(
                "OperationAwarePolicyRule requires at least one of `match` or `conditions` "
                "to be present and non-empty; a rule with neither is an unconditional rule "
                "and is not permitted."
            )
        return self

    @model_validator(mode="after")
    def _check_condition_id_uniqueness(self) -> OperationAwarePolicyRule:
        seen: set[str] = set()
        for condition in self.conditions or ():
            if condition.condition_id in seen:
                raise ValueError(
                    "OperationAwarePolicyRule.conditions contains a duplicate condition_id "
                    f"{condition.condition_id!r}; condition_id values must be unique within "
                    "one rule."
                )
            seen.add(condition.condition_id)
        return self
