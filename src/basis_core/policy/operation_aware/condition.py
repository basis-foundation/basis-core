"""
basis_core.policy.operation_aware.condition — the `PolicyCondition` data
model.

This module is the first module added under `src/basis_core/policy/
operation_aware/` for `basis-core` v0.2.0 (see
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`, Milestone 4,
PR 12 — "PolicyCondition model"). It implements exactly the shape published
by `basis-schemas` v0.2.0's `policy-condition` contract (ADR-0004 §7;
`policy-condition.md`):

  PolicyCondition   A single, inert, data-only predicate: a stable
                    condition identifier, a validated dotted field-path
                    reference into the categories published by
                    `operation-aware-decision-request`, an open (not
                    closed-enum) operator identifier, and a smallest-safe-
                    representation expected value (string, number, boolean,
                    null, or a homogeneous array of string/number/boolean
                    scalars).

Architectural boundary — structural shape only, no evaluation
────────────────────────────────────────────────────────────────
This module publishes the condition *shape*. It does not implement, and
must never grow, condition evaluation, match/no-match/error determination,
field-path resolution, or operator dispatch:
  - `field_path` is validated as a structurally well-formed dotted
    identifier path only. This module never imports, inspects, or
    traverses `OperationAwareDecisionRequest`; a structurally valid field
    path is not a claim that any given path is currently supported.
  - `operator` is validated as a structurally well-formed, open,
    extensible identifier only. This module defines no closed `Operator`
    enum and no operator whitelist — a structurally valid but semantically
    unimplemented operator (e.g. an invented future operator name) is
    accepted exactly like any illustrative operator named in the vendored
    contract. Which operators a given `field_path`/`expected_value`
    combination actually supports is future `basis-core` policy-validation
    work (Milestone 7 onward), not this module.
  - `expected_value` is restricted to inert, data-only scalars and
    homogeneous arrays of those scalars. No nested object, no nested array,
    no heterogeneous array, no function, no code, no template, and no
    executable expression of any kind can be constructed here.

Condition execution (match/no-match/error determination, operator
dispatch, field-path resolution against a real request) is implemented
separately, in `operators.py` (Milestone 7, PR 22 — the architecture
clarification named in Section 8 was approved and is now the governing
source for that module's behavior). This module remains inert structural
data only and implements none of it; `PolicyCondition` gains no
`evaluate()`/`matches()` method and no execution behavior of any kind.

Not implemented by this module (deferred to later, separately-scoped
roadmap PRs): `OperationAwarePolicyRule` (PR 13), `PolicyBundle` (PR 14),
rule-level condition-array iteration and aggregation (PR 23, built on top
of `operators.py`'s standalone evaluation), and any trace/audit assembly
that would reference conditions (Milestone 8+).

Import boundary
────────────────
This module depends on the standard library and `pydantic` only. It does
not import `basis_core.decisions`, `basis_core.enforcement`,
`basis_core.audit`, `basis_core.adapters`, `basis_core.policy.engine`, or
`basis_core.policy.rules` — condition data remains structurally independent
from runtime policy evaluation and from the existing v0.1.0 `PolicyRule`
Protocol. It does not import `OperationAwareDecisionRequest` or any other
operation-aware domain module — see "structural shape only" above.

Public API status: internal to the operation-aware package for now, exactly
like every other operation-aware module added so far. Not re-exported from
`basis_core.policy` or any other package `__init__.py`; see
`docs/public-api.md`'s "Open API questions" convention and Section 6 of the
roadmap plan for when operation-aware symbols are expected to graduate to
the stable public API (Milestone 11, PR 35).
"""

from __future__ import annotations

import math
import re

from pydantic import (
    BaseModel,
    ConfigDict,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    field_validator,
)

# Structural patterns, copied verbatim from the vendored `policy-condition`
# contract's `field_path_pattern` / `operator_pattern`. Structural shape
# only — neither pattern enumerates or closes a set of supported request
# field paths or operators; see this module's docstring.
_FIELD_PATH_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$")
_OPERATOR_RE = re.compile(r"^[a-z][a-z0-9]*(_[a-z0-9]+)*$")

# `expected_value`'s permitted array-item scalar types, per the vendored
# contract's `expected_value_array_item_types` (string, number, boolean —
# explicitly not `null`). Distinguished by "family", not exact Python type:
# `bool` is its own family (never conflated with `int`/`float`, even though
# Python's `bool` is an `int` subclass); `int` and `float` share one
# "number" family (the contract publishes a single `number` type, not
# separate `integer`/`number` types — see this module's tests and the PR 12
# final report for the fixture basis of this reading).
_FAMILY_BOOLEAN = "boolean"
_FAMILY_NUMBER = "number"
_FAMILY_STRING = "string"

# The scalar union `expected_value` accepts when not an array. `StrictBool`
# is listed before `StrictInt`/`StrictFloat` so pydantic's smart-union
# resolution never has to fall back to non-strict coercion to disambiguate
# a `bool` from an `int` — all four scalar members, plus `None`, use their
# strict pydantic form so no member silently coerces another member's
# value (e.g. `1` is never accepted as `True`, `"1"` is never accepted as
# `1`).
ExpectedScalar = StrictBool | StrictInt | StrictFloat | StrictStr | None

# `expected_value`'s homogeneous-array form. Each member list is restricted
# to one item family: a boolean array, a string array, or a number array
# whose items may freely mix `int` and `float` (same family — see
# `_FAMILY_NUMBER` above). Homogeneity *across* families (e.g. rejecting a
# string mixed with a number) is enforced by this module's `mode="before"`
# validator, not by this annotation alone — pydantic's union resolution
# picks whichever single list-member type matches every item, which is
# sufficient once the before-validator has already rejected any
# cross-family mix.
ExpectedValueArray = list[StrictBool] | list[StrictInt | StrictFloat] | list[StrictStr]

# The full `expected_value` union: a scalar, or a homogeneous array of
# scalars. Kept local to this module (not a broadly reusable production
# abstraction) per the roadmap plan's PR 12 scope.
ExpectedValue = ExpectedScalar | ExpectedValueArray


def _require_non_empty(value: str, *, field_name: str) -> str:
    """Shared non-empty/non-whitespace-only check for `PolicyCondition`'s
    two required string fields (`condition_id`, `field_path`) — the same
    convention every other required non-empty string field in this
    repository's operation-aware modules already follows (see
    `domain/evidence.py`, `domain/operation_aware.py`)."""
    if not value.strip():
        raise ValueError(f"PolicyCondition.{field_name} must not be empty or whitespace-only.")
    return value


def _classify_scalar(item: object) -> tuple[str, object]:
    """Classify one `expected_value` array item into its family
    (`_FAMILY_BOOLEAN`/`_FAMILY_NUMBER`/`_FAMILY_STRING`) and validate it,
    rejecting anything not a bool/int/float/str (in particular: `None`,
    mappings, and nested sequences — arrays may not contain `null`,
    objects, or nested arrays; see `expected_value_array_item_types` in the
    vendored contract, which excludes `null` even though the top-level
    scalar form allows it)."""
    if isinstance(item, bool):
        return _FAMILY_BOOLEAN, item
    if isinstance(item, int):
        return _FAMILY_NUMBER, item
    if isinstance(item, float):
        if not math.isfinite(item):
            raise ValueError(
                "PolicyCondition.expected_value array items must be finite numbers "
                "(NaN and Infinity are not JSON-compatible)."
            )
        return _FAMILY_NUMBER, item
    if isinstance(item, str):
        return _FAMILY_STRING, item
    raise ValueError(
        "PolicyCondition.expected_value array items must be a string, number, or "
        f"boolean; got {type(item).__name__}. Nested objects and nested arrays are "
        "not permitted."
    )


def _validate_expected_value(value: object) -> object:
    """Full `mode="before"` validation for `expected_value`, applied ahead
    of pydantic's own union-type check (see `ExpectedValue` above).

    Accepts: `None`; a `bool`; a finite `int`/`float`; a `str`; or a `list`
    whose items are all the same scalar family (`_classify_scalar`) — an
    empty list is accepted (the vendored contract documents no `minItems`
    constraint on `expected_value`; see this module's tests and the PR 12
    final report). Rejects: NaN/Infinity, mappings, nested sequences inside
    an array, and any array whose items span more than one family (e.g. a
    string mixed with a number, or a boolean mixed with a number).
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(
                "PolicyCondition.expected_value must be a finite number (NaN and "
                "Infinity are not JSON-compatible)."
            )
        return value
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        if len(value) == 0:
            return value
        families_and_items = [_classify_scalar(item) for item in value]
        families = {family for family, _ in families_and_items}
        if len(families) > 1:
            raise ValueError(
                "PolicyCondition.expected_value array items must all belong to the "
                f"same scalar family (string, number, or boolean); got a mix: "
                f"{sorted(families)}."
            )
        return [item for _, item in families_and_items]
    raise ValueError(
        "PolicyCondition.expected_value must be a string, a number, a boolean, an "
        "explicit null, or a homogeneous array of those scalars; got "
        f"{type(value).__name__}. Nested objects are not permitted."
    )


class PolicyCondition(BaseModel):
    """
    A single, inert, data-only condition predicate — the shape published
    by `basis-schemas` v0.2.0's `policy-condition` contract (ADR-0004 §7).

    A condition is a deterministic, side-effect-free test description over
    operation-aware request context. This type carries the test's
    *description* only; it never executes anything. See this module's
    docstring for the full "structural shape only" boundary.

    Required fields
    ────────────────
    condition_id    Stable identifier for this condition, unique within its
                     containing rule (rule-level uniqueness — a standalone
                     condition has no sibling conditions to compare
                     against, so this type cannot and does not enforce
                     uniqueness itself). Non-empty; no pattern beyond that.
    field_path      A validated dotted identifier path into the
                     operation-aware request context (e.g.
                     ``"subject_attrs.clearance"``, ``"location.site_id"``,
                     ``"device.device_class"``). Structural validation
                     only — no method-call syntax, no array-indexing
                     syntax, no function calls, and no executable
                     expression of any kind. A structurally valid path is
                     not a claim that `basis-core` currently supports
                     evaluating it.
    operator        An open, extensible, lowercase snake_case operator
                     identifier (e.g. ``"equals"``, ``"greater_than"``, or
                     any other structurally well-formed identifier,
                     including one not yet implemented anywhere). Not a
                     closed enum; this type defines no operator whitelist
                     and performs no operator dispatch.
    expected_value  The data-only value this condition would compare the
                     referenced field against: a string, a number, a
                     boolean, an explicit `None`, or a homogeneous array of
                     string/number/boolean scalars. Required — the key must
                     always be present — but its value may legitimately be
                     `None` itself (an explicit null comparison is a
                     meaningful data value here, not an absence marker).

    This type performs no evaluation: no `evaluate()`, no `matches()`, no
    field-path resolution, no operator dispatch, and no comparison of any
    kind.
    """

    condition_id: str
    field_path: str
    operator: str
    expected_value: ExpectedValue

    model_config = ConfigDict(frozen=True, extra="forbid")

    @field_validator("condition_id", mode="after")
    @classmethod
    def condition_id_must_not_be_empty(cls, v: str) -> str:
        return _require_non_empty(v, field_name="condition_id")

    @field_validator("field_path", mode="after")
    @classmethod
    def field_path_must_be_well_formed(cls, v: str) -> str:
        v = _require_non_empty(v, field_name="field_path")
        if not _FIELD_PATH_RE.match(v):
            raise ValueError(
                f"PolicyCondition.field_path {v!r} does not match the required pattern "
                r"'^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$' (lowercase dot-separated "
                "identifier segments only — no method calls, array-indexing syntax, "
                "function calls, or executable expressions)."
            )
        return v

    @field_validator("operator", mode="after")
    @classmethod
    def operator_must_be_well_formed(cls, v: str) -> str:
        v = _require_non_empty(v, field_name="operator")
        if not _OPERATOR_RE.match(v):
            raise ValueError(
                f"PolicyCondition.operator {v!r} does not match the required pattern "
                r"'^[a-z][a-z0-9]*(_[a-z0-9]+)*$' (lowercase snake_case). This pattern "
                "is structural only — it does not enumerate a closed set of supported "
                "operators; any structurally well-formed identifier is accepted."
            )
        return v

    @field_validator("expected_value", mode="before")
    @classmethod
    def expected_value_must_be_scalar_or_homogeneous_array(cls, v: object) -> object:
        return _validate_expected_value(v)
