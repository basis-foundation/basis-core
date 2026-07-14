"""
basis_core.policy.operation_aware.operators — the condition operator
registry and standalone `PolicyCondition` evaluation (Milestone 7, PR 22 of
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`: "Condition
operator registry implementation").

This module implements exactly the ten-operator subset approved by the
`basis-architecture` clarification `docs/architecture/condition-operator-
semantics.md` (merged to `basis-architecture` `main`; see this PR's final
report for the exact commit hash read). That document — not this module's
docstring, not the roadmap plan, and not ADR-0004 §7 in isolation — is the
authoritative source for every behavior implemented here. Where this
docstring restates a rule, the restatement is a summary of the approved
clarification, not an independent decision.

  ConditionResult      The closed, three-value condition-evaluation result
                       vocabulary: `match` / `no_match` / `error`. This is
                       not an authorization outcome (`allow`/`deny`) and not
                       a rule-level result (`matched`/`not_matched`/
                       `skipped`/`error`, `TraceRuleEvidence.rule_result`,
                       Milestone 8) — it is exactly, and only, the
                       condition-evaluation-stage classification the
                       approved clarification's §3, §19, and §24 define.
  ConditionEvaluation  An immutable `(condition_id, result)` pair — the
                       smallest result shape that identifies which
                       condition was evaluated and distinguishes
                       match/no_match/error without exposing raw actual or
                       expected values, exception objects, or a reason-code
                       vocabulary this PR does not own.
  evaluate_condition() The single public entry point. A pure function:
                       `(PolicyCondition, OperationAwareDecisionRequest) ->
                       ConditionEvaluation`.
  SUPPORTED_OPERATORS  The exact, approved, finite ten-operator set this
                       kernel version implements, exposed as a public,
                       immutable `frozenset[str]` so the registry's
                       closedness can be asserted directly without reaching
                       into a private mapping.

Architectural boundary — one condition, one request, nothing else
────────────────────────────────────────────────────────────────────────
`evaluate_condition` evaluates exactly one already-constructed
`PolicyCondition` against exactly one already-constructed
`OperationAwareDecisionRequest`. It does not implement, and must never grow:
  - rule-level condition-array iteration or aggregation (any condition
    `error` makes the rule `error`; all conditions must match for
    `matched`) — that is PR 23's `condition_eval.py`.
  - selector integration — `selector.py`'s `conditions_pending` boundary is
    unchanged by this module and this module is not imported by it.
  - `TraceRuleEvidence.condition_results` population, `EvaluationTrace`
    assembly, or any other trace/audit shape — Milestone 8 onward.
  - rule effects, deny precedence, default deny, or any final authorization
    outcome — Milestone 9 onward.

Open contract, finite runtime capability
────────────────────────────────────────────────────────────────────────
`PolicyCondition.operator` (`condition.py`, PR 12) remains an open,
structurally validated identifier — this module does not add a closed
`Operator` enum to `condition.py` and does not reject unsupported operators
at construction time. A structurally valid operator this kernel version does
not implement (for example a synthetic `future_operator`) constructs a
`PolicyCondition` successfully and evaluates to `ConditionResult.ERROR` —
never a silent `no_match`, never a silent `match`, and never an unhandled
exception. This is the approved clarification's §5 "Operator Vocabulary
Boundary", restated here as the binding implementation behavior.

Field-path resolution — bounded, typed, no reflection
────────────────────────────────────────────────────────────────────────
Resolution begins and ends at one root: the `OperationAwareDecisionRequest`
instance passed to `evaluate_condition`. Traversal is explicit, bounded
typed-attribute access against a hardcoded set of known fields on
`OperationAwareDecisionRequest` and its six nested context objects
(`OperationAwareLocation`, `OperationAwareDevice`,
`OperationAwareProtocolContext`, `OperationAwareSafetyContext`,
`OperationAwareEnvironmentContext`, `OperationAwareRiskContext`) — never a
generic `getattr` chain over arbitrary object state, never `eval`/`exec`,
never dict-of-everything lookup, with the one named exception of
`subject_attrs` (a bounded, one-level `dict[str, str]` key lookup, per the
approved clarification's §6.6). `identity_evidence_reference` and
`adapter_evidence_reference` are excluded from the addressable field-path
surface at any depth (§6.7) — resolving to the same `error` outcome as any
other unknown path (§6.5), never fetched, never inspected.

Absent vs. unknown — two distinct outcomes, never conflated
────────────────────────────────────────────────────────────────────────
This module distinguishes exactly two path-resolution states beyond a
successfully resolved value: ABSENT (a known, declared field or
`subject_attrs` key that this particular request did not populate — every
optional field on this request model is `T | None = None`, so "omitted" and
"explicit null" are not observable as distinct states; see the approved
clarification's §7) and UNKNOWN (a field path that is not a field this
kernel version's request model declares at all, or that reaches past a
scalar leaf, or that names an excluded evidence-reference field). ABSENT
feeds each operator's own per-operator absence rule (§4, §15); UNKNOWN
always produces `ConditionResult.ERROR` (§6.5), independent of which
operator was named.

No coercion, no silent type conversion
────────────────────────────────────────────────────────────────────────
Every comparison operator classifies the actual value and the expected
value into one of a small set of families (`string`, `number` — int and
float unified, never boolean — `boolean`, `array`, `timestamp`, or
`structured_object`) and requires the operator's own accepted families to
match before comparing. A family mismatch is always `ConditionResult.ERROR`
— never an implicit `str()`/`int()`/`float()`/`bool()` conversion, and never
a silent `no_match` standing in for "could not be compared" (§9, §16).

Security and determinism
────────────────────────────────────────────────────────────────────────
This module performs no network access, no filesystem access, no database
access, no subprocess execution, no dynamic imports, no `eval`/`exec`, no
templates, no regular-expression evaluation of request values, no
environment-variable lookup, and no live-clock access — `evaluation_time` is
read from the request the caller supplied, never sampled from the system
clock. `evaluate_condition` never mutates `condition`, `request`, or any
nested value reachable from either; identical inputs always produce an
identical `ConditionEvaluation`.

Not implemented by this module (deferred to later, separately-scoped
roadmap PRs): rule-level condition iteration/aggregation and
`condition_eval.py` (PR 23); `TraceRuleEvidence`/`EvaluationTrace` (Milestone
8); `OperationAwarePolicyEngine`, deny precedence, default deny, and any
final authorization outcome (Milestone 9 onward). Also explicitly deferred,
per the approved clarification's own §26 "Open Questions Deferred":
array-typed actual values as operands to any operator beyond
`exists`/`not_exists` ("any of"/"all of" semantics); timestamp-aware
ordering; string ordering; mapping-key traversal for any field other than
`subject_attrs`; case-insensitive comparison, whitespace normalization, or
value aliasing; regular-expression-based operators.

Import boundary
────────────────
This module depends on the standard library, `basis_core.decisions.
operation_aware.OperationAwareDecisionRequest` (reused, not duplicated — the
same dependency `selector.py`, PR 19, already establishes as legitimate
`policy/` precedent), and `basis_core.policy.operation_aware.condition.
PolicyCondition` (reused, not duplicated). It does not import
`basis_core.audit`, `basis_core.enforcement`, `basis_core.adapters`,
`basis_core.policy.engine`, `basis_core.policy.rules`, or any external
framework, protocol, or cloud library.

Public API status: internal to the operation-aware package for now, exactly
like every other operation-aware module added so far. Not re-exported from
`basis_core.policy` or any other package `__init__.py`; see
`docs/public-api.md`'s "Open API questions" convention and Section 6 of the
roadmap plan for when operation-aware symbols are expected to graduate to
the stable public API (Milestone 11, PR 35).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from types import MappingProxyType
from typing import Any, cast

from basis_core.decisions.operation_aware import OperationAwareDecisionRequest
from basis_core.policy.operation_aware.condition import PolicyCondition

__all__ = [
    "ConditionEvaluation",
    "ConditionResult",
    "SUPPORTED_OPERATORS",
    "evaluate_condition",
]


# ══════════════════════════════════════════════════════════════════════════
# Result vocabulary
# ══════════════════════════════════════════════════════════════════════════


class ConditionResult(str, Enum):
    """
    The closed, three-value condition-evaluation result vocabulary.

    Closed to exactly `match` / `no_match` / `error` (the approved
    clarification's §3, §19, §24). Not an authorization outcome
    (`allow`/`deny`/`not_applicable`) and not a rule-level result
    (`matched`/`not_matched`/`skipped`/`error`) — those are later,
    separately-scoped concepts (PR 23 onward, Milestone 9 onward). This
    module never produces, and never needs, any other member.
    """

    MATCH = "match"
    NO_MATCH = "no_match"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class ConditionEvaluation:
    """
    The immutable result of evaluating one `PolicyCondition` against one
    `OperationAwareDecisionRequest`.

    Two fields, both required:
      condition_id  The evaluated condition's own `condition_id` — enough
                    to identify which condition this result belongs to
                    without a caller needing to keep the original
                    `PolicyCondition` object alongside this result.
      result        The `ConditionResult` — `match`, `no_match`, or `error`.

    Deliberately minimal: no raw actual value, no raw expected value, no
    exception object, no stack trace, no full request serialization, and no
    error-code/reason-code field. The approved clarification's error
    semantics (§19) require a stable, deterministic three-outcome result —
    not a governed reason-code vocabulary, which this PR does not own and
    does not invent. A plain, frozen `dataclasses.dataclass` — not a
    Pydantic model — for the same reason `selector.py`'s
    `SelectorEvaluation` is one: a pure in-process function result, never
    constructed from untrusted wire input, never serialized on its own, and
    requiring no field validation beyond what `ConditionResult` already
    enforces.

    This type does not preempt a future trace contract:
    `TraceRuleEvidence.condition_results` (Milestone 8 onward) is free to
    represent per-condition results in whatever shape that later,
    separately-scoped contract requires — this module makes no assumption
    about it and defines no `TraceConditionResult` type.
    """

    condition_id: str
    result: ConditionResult


# ══════════════════════════════════════════════════════════════════════════
# Field-path resolution — bounded, typed traversal only
# ══════════════════════════════════════════════════════════════════════════


class _PathStatus(Enum):
    """Internal, non-public field-path resolution states. Not the same
    vocabulary as `ConditionResult` — this is a resolution-stage concept,
    consumed only by the operator functions below, never returned to a
    caller of `evaluate_condition` on its own."""

    PRESENT = "present"
    ABSENT = "absent"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class _PathResolution:
    """Internal, non-public field-path resolution result. `value` is
    meaningful only when `status is _PathStatus.PRESENT`; it is always
    `None` for `ABSENT`/`UNKNOWN` (never itself used to distinguish those
    two — `status` alone does that)."""

    status: _PathStatus
    value: object = None


# Top-level `OperationAwareDecisionRequest` fields resolvable as a single
# path segment. Excludes `identity_evidence_reference`/
# `adapter_evidence_reference` (handled separately — always UNKNOWN, per
# the approved clarification's §6.7) and the six nested context objects
# (handled separately below, as two-segment paths).
_TOP_LEVEL_SCALAR_ACCESSORS: Mapping[str, Callable[[OperationAwareDecisionRequest], object]] = (
    MappingProxyType(
        {
            "request_id": lambda r: r.request_id,
            "correlation_id": lambda r: r.correlation_id,
            "subject_id": lambda r: r.subject_id,
            "subject_roles": lambda r: r.subject_roles,
            "identity_source": lambda r: r.identity_source,
            "authority_mode": lambda r: r.authority_mode,
            "action": lambda r: r.action,
            "resource": lambda r: r.resource,
            "resource_type": lambda r: r.resource_type,
            # Enum-backed: resolved to its canonical `.value` string (the
            # approved clarification's §9.1), never the enum object itself.
            "operation_intent": lambda r: (
                r.operation_intent.value if r.operation_intent is not None else None
            ),
            "evaluation_time": lambda r: r.evaluation_time,
            "expected_policy_version": lambda r: r.expected_policy_version,
        }
    )
)

# The six nested, independently-optional context objects. Each maps its
# field name to an accessor returning the (possibly absent) parent object
# itself.
_NESTED_PARENTS: Mapping[str, Callable[[OperationAwareDecisionRequest], object]] = MappingProxyType(
    {
        "location": lambda r: r.location,
        "device": lambda r: r.device,
        "protocol_context": lambda r: r.protocol_context,
        "safety_context": lambda r: r.safety_context,
        "environment_context": lambda r: r.environment_context,
        "risk_context": lambda r: r.risk_context,
    }
)

# Every declared leaf field on each of the six nested context objects.
# Exhaustive against `domain/operation_aware.py`'s current field set — a
# leaf not named here is an unknown nested path (§6.5), never guessed.
# Parameter typed `Any` (not `object`) purely so mypy accepts the bounded,
# per-class attribute access below; the outer key (e.g. "location") already
# statically determines which one of the six known typed context classes
# each inner accessor is called with — this is a typing-only relaxation,
# not a broadening of what is actually accessed at runtime.
_NESTED_LEAF_ACCESSORS: Mapping[str, Mapping[str, Callable[[Any], object]]] = MappingProxyType(
    {
        "location": MappingProxyType(
            {
                "site_id": lambda o: o.site_id,
                "building_id": lambda o: o.building_id,
                "zone_id": lambda o: o.zone_id,
                "area_id": lambda o: o.area_id,
            }
        ),
        "device": MappingProxyType(
            {
                "device_id": lambda o: o.device_id,
                "device_class": lambda o: o.device_class,
            }
        ),
        "protocol_context": MappingProxyType(
            {
                "protocol": lambda o: o.protocol,
                "operation": lambda o: o.operation,
            }
        ),
        "safety_context": MappingProxyType(
            {
                "mode": lambda o: o.mode,
                "classification": lambda o: o.classification,
                "constraint_ids": lambda o: o.constraint_ids,
            }
        ),
        "environment_context": MappingProxyType(
            {
                "mode": lambda o: o.mode,
                "condition_ids": lambda o: o.condition_ids,
            }
        ),
        "risk_context": MappingProxyType(
            {
                "classification": lambda o: o.classification,
                "score": lambda o: o.score,
            }
        ),
    }
)

# Excluded from the addressable condition field-path surface at any depth
# (the approved clarification's §6.7). Any `field_path` beginning with
# either name — the bare field or any nested sub-field — resolves as
# UNKNOWN, identically to a genuinely unrecognized path.
_EXCLUDED_EVIDENCE_REFERENCE_ROOTS = frozenset(
    {"identity_evidence_reference", "adapter_evidence_reference"}
)


def _resolve_field_path(request: OperationAwareDecisionRequest, field_path: str) -> _PathResolution:
    """
    Resolve `field_path` against `request`, returning exactly one of
    PRESENT (with the resolved value), ABSENT, or UNKNOWN.

    See this module's docstring, "Field-path resolution", for the full
    governing rules. Summary of this function's branching, in the order
    checked:

      1. `identity_evidence_reference`/`adapter_evidence_reference` (any
         depth) → UNKNOWN (§6.7).
      2. `subject_attrs` (bare) → PRESENT (the mapping itself — always
         present, even when empty; `subject_attrs` defaults to `{}`, never
         `None`).
      3. `subject_attrs.<key>` (exactly one segment past `subject_attrs`)
         → PRESENT (the string value) if `<key>` is in the mapping, else
         ABSENT. Never an error — an unpopulated ABAC key is routine (§6.6).
      4. `subject_attrs.<key>.<anything>` (two or more segments past
         `subject_attrs`) → UNKNOWN — `subject_attrs` values are always
         plain strings, so a second-level segment cannot resolve to
         anything (§6.6).
      5. One of the six nested context object names, bare → PRESENT (the
         object itself) if not `None`, else ABSENT.
      6. One of the six nested context object names, plus exactly one
         declared leaf segment → PRESENT (the leaf value) if the parent is
         present and the leaf is not `None`; ABSENT if the parent is
         absent (§6.3) or the leaf is `None` (§6.4) — both collapse to the
         same ABSENT outcome, never distinguished.
      7. One of the six nested context object names, plus an undeclared
         leaf segment, or more than one segment past the object name →
         UNKNOWN.
      8. One of the declared top-level scalar fields, exactly one segment
         → PRESENT (the value, or the enum's `.value` for
         `operation_intent`) if not `None`, else ABSENT.
      9. Anything else (an undeclared top-level field name, or extra
         segments past a scalar leaf) → UNKNOWN.
    """
    segments = field_path.split(".")
    first = segments[0]

    if first in _EXCLUDED_EVIDENCE_REFERENCE_ROOTS:
        return _PathResolution(_PathStatus.UNKNOWN)

    if first == "subject_attrs":
        if len(segments) == 1:
            return _PathResolution(_PathStatus.PRESENT, request.subject_attrs)
        if len(segments) == 2:
            key = segments[1]
            if key in request.subject_attrs:
                return _PathResolution(_PathStatus.PRESENT, request.subject_attrs[key])
            return _PathResolution(_PathStatus.ABSENT)
        return _PathResolution(_PathStatus.UNKNOWN)

    if first in _NESTED_PARENTS:
        parent_accessor = _NESTED_PARENTS[first]
        if len(segments) == 1:
            parent = parent_accessor(request)
            if parent is None:
                return _PathResolution(_PathStatus.ABSENT)
            return _PathResolution(_PathStatus.PRESENT, parent)
        if len(segments) == 2:
            leaf_accessors = _NESTED_LEAF_ACCESSORS[first]
            leaf = segments[1]
            if leaf not in leaf_accessors:
                return _PathResolution(_PathStatus.UNKNOWN)
            parent = parent_accessor(request)
            if parent is None:
                return _PathResolution(_PathStatus.ABSENT)
            value = leaf_accessors[leaf](parent)
            if value is None:
                return _PathResolution(_PathStatus.ABSENT)
            return _PathResolution(_PathStatus.PRESENT, value)
        return _PathResolution(_PathStatus.UNKNOWN)

    if len(segments) == 1 and first in _TOP_LEVEL_SCALAR_ACCESSORS:
        value = _TOP_LEVEL_SCALAR_ACCESSORS[first](request)
        if value is None:
            return _PathResolution(_PathStatus.ABSENT)
        return _PathResolution(_PathStatus.PRESENT, value)

    return _PathResolution(_PathStatus.UNKNOWN)


# ══════════════════════════════════════════════════════════════════════════
# Type classification — families the architecture governs, not Python
# ══════════════════════════════════════════════════════════════════════════

_FAMILY_STRING = "string"
_FAMILY_NUMBER = "number"
_FAMILY_BOOLEAN = "boolean"
_FAMILY_ARRAY = "array"
_FAMILY_TIMESTAMP = "timestamp"
_FAMILY_STRUCTURED_OBJECT = "structured_object"
_FAMILY_NULL = "null"

# The only actual-value families any comparison operator in this registry
# ever accepts (§8, §12, §13). `exists`/`not_exists` never consult this —
# they only test `_PathStatus`, never a value's family.
_SCALAR_COMPARISON_FAMILIES = frozenset({_FAMILY_STRING, _FAMILY_NUMBER, _FAMILY_BOOLEAN})


def _family_of_actual(value: object) -> str:
    """
    Classify a PRESENT actual value into one family, per the approved
    clarification's §9 type system. Order matters: `bool` is checked
    before `int`/`float` because Python's `bool` is an `int` subclass —
    this evaluator never inherits that behavior (§9.2), so a boolean is
    always classified `boolean`, never `number`.
    """
    if isinstance(value, bool):
        return _FAMILY_BOOLEAN
    if isinstance(value, (int, float)):
        return _FAMILY_NUMBER
    if isinstance(value, str):
        return _FAMILY_STRING
    if isinstance(value, datetime):
        return _FAMILY_TIMESTAMP
    if isinstance(value, (list, tuple)):
        return _FAMILY_ARRAY
    # Nested context objects (frozen Pydantic models) and the bare
    # `subject_attrs` mapping. Only `exists`/`not_exists` are meaningful
    # against this family (§9); every comparison operator below rejects it
    # via `_SCALAR_COMPARISON_FAMILIES`.
    return _FAMILY_STRUCTURED_OBJECT


def _family_of_expected_scalar(value: object) -> str | None:
    """
    Classify an `expected_value` as a scalar family (`null`/`boolean`/
    `number`/`string`), or return `None` if it is not a scalar (i.e. it is
    an array — a malformed operand for `equals`/`not_equals` and every
    ordering operator, per §8 and §13). Never called for `in`/`not_in`,
    which interpret `expected_value` as an array directly.
    """
    if value is None:
        return _FAMILY_NULL
    if isinstance(value, bool):
        return _FAMILY_BOOLEAN
    if isinstance(value, (int, float)):
        return _FAMILY_NUMBER
    if isinstance(value, str):
        return _FAMILY_STRING
    return None


# ══════════════════════════════════════════════════════════════════════════
# Operator implementations
# ══════════════════════════════════════════════════════════════════════════

_OperatorFn = Callable[[_PathResolution, object], ConditionResult]


def _op_equals(resolution: _PathResolution, expected: object) -> ConditionResult:
    """`equals` — §8, §24."""
    if resolution.status is not _PathStatus.PRESENT:
        return ConditionResult.NO_MATCH
    actual_family = _family_of_actual(resolution.value)
    if actual_family not in _SCALAR_COMPARISON_FAMILIES:
        return ConditionResult.ERROR
    expected_family = _family_of_expected_scalar(expected)
    if expected_family is None or expected_family == _FAMILY_NULL:
        # Array expected_value, or expected_value: null against a PRESENT
        # (therefore never-null-family) actual value — both are family
        # mismatches for `equals`.
        return ConditionResult.ERROR
    if expected_family != actual_family:
        return ConditionResult.ERROR
    return ConditionResult.MATCH if resolution.value == expected else ConditionResult.NO_MATCH


def _op_not_equals(resolution: _PathResolution, expected: object) -> ConditionResult:
    """`not_equals` — §8, §24. Absence is never treated as satisfying
    inequality."""
    if resolution.status is not _PathStatus.PRESENT:
        return ConditionResult.NO_MATCH
    actual_family = _family_of_actual(resolution.value)
    if actual_family not in _SCALAR_COMPARISON_FAMILIES:
        return ConditionResult.ERROR
    expected_family = _family_of_expected_scalar(expected)
    if expected_family is None or expected_family == _FAMILY_NULL:
        return ConditionResult.ERROR
    if expected_family != actual_family:
        return ConditionResult.ERROR
    return ConditionResult.NO_MATCH if resolution.value == expected else ConditionResult.MATCH


def _op_in(resolution: _PathResolution, expected: object) -> ConditionResult:
    """`in` — §12, §24."""
    if resolution.status is not _PathStatus.PRESENT:
        return ConditionResult.NO_MATCH
    actual_family = _family_of_actual(resolution.value)
    if actual_family not in _SCALAR_COMPARISON_FAMILIES:
        return ConditionResult.ERROR
    if not isinstance(expected, list):
        return ConditionResult.ERROR
    if len(expected) == 0:
        return ConditionResult.NO_MATCH
    element_family = _family_of_expected_scalar(expected[0])
    if element_family != actual_family:
        return ConditionResult.ERROR
    return (
        ConditionResult.MATCH
        if any(resolution.value == item for item in expected)
        else ConditionResult.NO_MATCH
    )


def _op_not_in(resolution: _PathResolution, expected: object) -> ConditionResult:
    """`not_in` — §12, §24."""
    if resolution.status is not _PathStatus.PRESENT:
        return ConditionResult.NO_MATCH
    actual_family = _family_of_actual(resolution.value)
    if actual_family not in _SCALAR_COMPARISON_FAMILIES:
        return ConditionResult.ERROR
    if not isinstance(expected, list):
        return ConditionResult.ERROR
    if len(expected) == 0:
        return ConditionResult.MATCH
    element_family = _family_of_expected_scalar(expected[0])
    if element_family != actual_family:
        return ConditionResult.ERROR
    return (
        ConditionResult.NO_MATCH
        if any(resolution.value == item for item in expected)
        else ConditionResult.MATCH
    )


def _gt(a: float, b: float) -> bool:
    return a > b


def _ge(a: float, b: float) -> bool:
    return a >= b


def _lt(a: float, b: float) -> bool:
    return a < b


def _le(a: float, b: float) -> bool:
    return a <= b


def _make_ordering_operator(compare: Callable[[float, float], bool]) -> _OperatorFn:
    """Shared implementation for the four ordering operators — §13, §24.
    Only the comparison callable differs between them."""

    def _op_ordering(resolution: _PathResolution, expected: object) -> ConditionResult:
        if resolution.status is not _PathStatus.PRESENT:
            return ConditionResult.NO_MATCH
        actual_family = _family_of_actual(resolution.value)
        if actual_family != _FAMILY_NUMBER:
            return ConditionResult.ERROR
        expected_family = _family_of_expected_scalar(expected)
        if expected_family != _FAMILY_NUMBER:
            return ConditionResult.ERROR
        # Both values are already confirmed `number`-family (int or float,
        # never bool) by the family checks above — this is a static type
        # narrowing for mypy, not a runtime coercion (no conversion
        # function is called; the underlying object is unchanged).
        actual_number = cast(float, resolution.value)
        expected_number = cast(float, expected)
        if compare(actual_number, expected_number):
            return ConditionResult.MATCH
        return ConditionResult.NO_MATCH

    return _op_ordering


_op_greater_than = _make_ordering_operator(_gt)
_op_greater_than_or_equal = _make_ordering_operator(_ge)
_op_less_than = _make_ordering_operator(_lt)
_op_less_than_or_equal = _make_ordering_operator(_le)


def _op_exists(resolution: _PathResolution, expected: object) -> ConditionResult:
    """`exists` — §4, §24. `expected_value` is required by the shared
    schema but is never interpreted here."""
    del expected
    return (
        ConditionResult.MATCH
        if resolution.status is _PathStatus.PRESENT
        else ConditionResult.NO_MATCH
    )


def _op_not_exists(resolution: _PathResolution, expected: object) -> ConditionResult:
    """`not_exists` — §4, §24. `expected_value` is required by the shared
    schema but is never interpreted here."""
    del expected
    return (
        ConditionResult.MATCH
        if resolution.status is _PathStatus.ABSENT
        else ConditionResult.NO_MATCH
    )


# ══════════════════════════════════════════════════════════════════════════
# Operator registry
# ══════════════════════════════════════════════════════════════════════════

# The exact, finite, approved ten-operator set (the approved clarification's
# §4). No aliases, no abbreviations, no synonyms, no entries beyond this
# set. `MappingProxyType` makes the registry read-only at the object level;
# there is no `register_operator()` API, no plugin loading, no
# environment-driven operator selection, and no dynamic import anywhere in
# this module — adding a future operator requires editing this literal
# mapping in a reviewed code change, never a runtime call.
_OPERATOR_REGISTRY: Mapping[str, _OperatorFn] = MappingProxyType(
    {
        "equals": _op_equals,
        "not_equals": _op_not_equals,
        "in": _op_in,
        "not_in": _op_not_in,
        "greater_than": _op_greater_than,
        "greater_than_or_equal": _op_greater_than_or_equal,
        "less_than": _op_less_than,
        "less_than_or_equal": _op_less_than_or_equal,
        "exists": _op_exists,
        "not_exists": _op_not_exists,
    }
)

# Public, immutable view of the supported operator set — for tests and
# future callers that need to assert the registry's exact closedness
# without importing a private mapping.
SUPPORTED_OPERATORS: frozenset[str] = frozenset(_OPERATOR_REGISTRY.keys())


# ══════════════════════════════════════════════════════════════════════════
# Public entry point
# ══════════════════════════════════════════════════════════════════════════


def evaluate_condition(
    condition: PolicyCondition,
    request: OperationAwareDecisionRequest,
) -> ConditionEvaluation:
    """
    Evaluate one `PolicyCondition` against one `OperationAwareDecisionRequest`.

    A pure, deterministic function. Never mutates `condition`, `request`, or
    any nested value reachable from either; never performs I/O, network
    access, filesystem access, environment lookup, or live-clock access;
    never raises for a normal semantic evaluation outcome (unsupported
    operator, unknown path, type mismatch, and every other case this
    module's docstring and the approved clarification define all become a
    `ConditionEvaluation` with `result=ConditionResult.ERROR`, not an
    exception propagated to the caller).

    Resolution order:
      1. Look up `condition.operator` in the finite, approved registry
         (§5). Not found → `ConditionResult.ERROR`.
      2. Resolve `condition.field_path` against `request` (see
         `_resolve_field_path`). An unknown path (§6.5, §6.7) →
         `ConditionResult.ERROR`, independent of which operator was named.
      3. Apply the looked-up operator to the resolution and
         `condition.expected_value`, producing `match`, `no_match`, or
         `error` per that operator's own rules (§4, §8, §12, §13, §24).

    Does not integrate with rule-level evaluation, selector output,
    condition-array iteration, condition aggregation, trace evidence, rule
    effects, or any final authorization outcome — see this module's
    docstring for the full PR 22/PR 23 boundary.

    Args:
        condition: an already-constructed, already-validated
            `PolicyCondition`.
        request: an already-constructed, already-validated
            `OperationAwareDecisionRequest`.

    Returns:
        A `ConditionEvaluation` carrying `condition.condition_id` and
        exactly one of `ConditionResult.MATCH`, `ConditionResult.NO_MATCH`,
        or `ConditionResult.ERROR`.
    """
    operator_fn = _OPERATOR_REGISTRY.get(condition.operator)
    if operator_fn is None:
        return ConditionEvaluation(
            condition_id=condition.condition_id, result=ConditionResult.ERROR
        )

    resolution = _resolve_field_path(request, condition.field_path)
    if resolution.status is _PathStatus.UNKNOWN:
        return ConditionEvaluation(
            condition_id=condition.condition_id, result=ConditionResult.ERROR
        )

    result = operator_fn(resolution, condition.expected_value)
    return ConditionEvaluation(condition_id=condition.condition_id, result=result)
