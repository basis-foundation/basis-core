"""
basis_core.policy.operation_aware.selector — rule match-criteria evaluation.

This module is the sixth module added under `src/basis_core/policy/
operation_aware/` for `basis-core` v0.2.0 (see
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`, Milestone 6,
PR 19 — "Rule match-criteria evaluator"), after PR 12's `condition.py`,
PR 13's `rule.py`, PR 14's `bundle.py`, PR 15's `validation.py`, and PR 17's
`applicability.py`. It implements the one deterministic classification named
by ADR-0004 §6 and `policy-rule.md` §11/§14 that neither `rule.py` (PR 13,
publishes the `match` *shape* only) nor `applicability.py` (PR 17, bundle
*scope*, not rule *match*) implements: whether one `OperationAwarePolicyRule`
`match` object structurally selects a given `OperationAwareDecisionRequest`.

  evaluate_rule_selectors()  The single public entry point. A pure function:
                             `(OperationAwarePolicyRule,
                             OperationAwareDecisionRequest) ->
                             SelectorEvaluation`.
  SelectorMatchResult        The closed, two-value selector-stage result
                              vocabulary (`matched` / `not_matched`).
  SelectorEvaluation          An immutable `(result, conditions_pending)`
                              pair — see "Condition boundary" below for why a
                              single two-value enum cannot honestly represent
                              this stage's outcome on its own.

Architectural boundary — structural match only, no conditions, no effect,
no outcome
────────────────────────────────────────────────────────────────────────
This module answers exactly one question: does this rule's `match` object
structurally select this request? It does not implement, and must never
grow: `PolicyCondition` evaluation (operator dispatch, field-path
resolution, expected-value comparison — see "Condition boundary" below),
`rule.effect` application, deny precedence, default deny, a final
authorization outcome (`ALLOW`/`DENY`/`NOT_APPLICABLE`), reason-code or
`explanation` interpolation, evaluation traces, decision responses, audit
evidence, bundle applicability (that is `applicability.py`, PR 17 — a
distinct, earlier pipeline stage this module depends on being already
satisfied by the time a rule reaches evaluation, but does not itself call
or duplicate), bundle/candidate-rule iteration, or rule ordering (PR 20).

Condition boundary — honest, conservative, visible
────────────────────────────────────────────────────────────────────────
`OperationAwarePolicyRule.conditions` remains inert data (`condition.py`'s
own documented boundary). `PolicyCondition` evaluation is blocked pending
the architecture clarification named in Section 8 of the roadmap plan
(Milestone 7, PRs 21-23), so this module never inspects a condition's
`operator`, `field_path`, or `expected_value` — a structurally valid but
semantically unimplemented operator (e.g. a synthetic `future_operator`) is
handled identically to any named operator, because neither is ever
examined here.

A rule whose structural `match` selectors all matched, but which still
carries one or more `conditions`, has NOT yet been shown to match: its
conditions have not been evaluated. Reporting such a rule as `matched`
would silently overstate what this module has actually checked, and would
let a future trace/response layer construct a decision without ever
consulting the rule's own declared conditions. `SelectorEvaluation`
therefore carries a second field, `conditions_pending`, alongside `result`
— a single `SelectorMatchResult.MATCHED` is never returned unless
`rule.conditions` is empty. See `evaluate_rule_selectors`'s docstring for
the exact four-case truth table this produces, and this module's final PR
report for why a single closed three-value enum
(`matched`/`not_matched`/`pending`) was deliberately not chosen instead:
that would either conflate "conditions pending after a full structural
match" with "conditions pending after a rule with no match object at all"
(both real but distinct causes), or would require inventing a state this
roadmap's own PR 19 entry does not authorize
(`allow`/`deny`/`error`/`skipped`/`not_applicable` are explicitly listed as
selector outcomes this PR must not create).

No bundle iteration in `evaluate_rule_selectors` itself
────────────────────────────────────────────────────────────────────────
`evaluate_rule_selectors` takes exactly one already-typed rule and one
already-typed request. It does not accept a `PolicyBundle`, a list of
rules, or any iterable of candidates, and does not sort, rank, or
tie-break anything itself. Deterministic multi-rule candidate ordering is
`select_candidate_rules`'s separate, additive responsibility (PR 20 — see
"PR 20 addition" below); it is implemented by calling
`evaluate_rule_selectors` once per rule, unchanged, never by duplicating
or reimplementing this function's single-rule logic.

Selector-to-request mapping (twenty categories, ADR-0004 §6 /
`policy-rule.yaml`'s `match_shape`)
────────────────────────────────────────────────────────────────────────
    Match selector           Request counterpart                    Comparison
    ───────────────────────  ──────────────────────────────────────  ───────────
    subject_ids               request.subject_id                      scalar
    subject_roles              request.subject_roles                   intersect
    identity_sources            request.identity_source                 scalar
    authority_modes               request.authority_mode                  scalar
    actions                       request.action                          scalar
    resources                      request.resource                        scalar
    resource_types                  request.resource_type                   scalar
    site_ids                        request.location.site_id                scalar
    building_ids                     request.location.building_id            scalar
    zone_ids                         request.location.zone_id                scalar
    area_ids                          request.location.area_id                scalar
    device_ids                        request.device.device_id                scalar
    device_classes                     request.device.device_class             scalar
    protocols                          request.protocol_context.protocol       scalar
    protocol_operations                 request.protocol_context.operation      scalar
    operation_intents                    request.operation_intent.value          scalar
    safety_modes                          request.safety_context.mode             scalar
    safety_classifications                 request.safety_context.classification   scalar
    environment_modes                       request.environment_context.mode        scalar
    risk_classifications                     request.risk_context.classification     scalar

    ("scalar" = exact scalar membership; "intersect" = any exact
    intersection between two collections — see `subject_roles` below.)

No `subject_attrs` selector
────────────────────────────────────────────────────────────────────────
`OperationAwareDecisionRequest` carries `subject_attrs` (an ABAC attribute
mapping), but `OperationAwarePolicyMatch` (`rule.py`, verified directly
against the current model and against the vendored `policy-rule.yaml`'s
`match_shape.optional` list — twenty entries, `subject_attrs` not among
them) publishes no corresponding selector. This module therefore does not
match `subject_attrs`, `subject_attribute_matches`, `claims`, or any
attribute-expression construct — inventing one here would broaden the
published contract, not merely fill a gap. See this module's final PR
report for the explicit roadmap-terminology-versus-published-contract note
("subject identity/attributes" in the roadmap's prose summary does not
expand the contract's actual twenty-selector `match_shape`).

Scalar semantics — no coercion, no normalization, no hierarchy
────────────────────────────────────────────────────────────────────────
Every scalar selector category is compared with exact-string membership
only, using the same shared primitive convention `applicability.py`
already established for bundle-scope matching: an absent selector imposes
no restriction; a populated selector requires the request's corresponding
value to be a member of the selector's array of alternatives; a request
that has no value at all for that dimension (either because a required
nested context object is itself absent, or because the object is present
but the specific field is `None`) cannot satisfy a populated selector — a
missing request counterpart is never treated as a wildcard, and nothing is
inferred, defaulted, derived from a sibling field, or fetched. No
lowercasing, uppercasing, trimming, aliasing, prefix/suffix/substring
matching, glob/regex/wildcard matching, or location/topology hierarchy
inference (site → building → zone → area, or the reverse) is implemented.
`resources`/`resource_types` and `protocols`/`protocol_operations` are
each treated as fully independent categories — neither is derived from,
or cross-checked against, the other.

`subject_roles` — the one collection-to-collection category
────────────────────────────────────────────────────────────────────────
`subject_roles` is the only selector whose request counterpart
(`request.subject_roles`) is itself a collection rather than a scalar.
Match semantics: any exact intersection between the selector's
alternatives and the request's roles is sufficient — not "all selector
roles present on the request" and not "all request roles present in the
selector". Selector/request ordering is never significant (both are
compared as sets of values, never compared element-by-element or by
position). An absent selector imposes no restriction; a populated selector
against a request with no roles at all (`request.subject_roles` defaults
to `[]` — never `None` on this model, so "omitted" and "empty" collapse
to the same observable state) never matches.

Combination semantics (`policy-rule.yaml`'s `match_semantics`)
────────────────────────────────────────────────────────────────────────
    within_selector    any_of    — any one alternative within one populated
                                   selector category is sufficient
    across_selectors   all_of    — every populated selector category must
                                   independently match (logical AND)
    absent_selector    no_restriction — an omitted selector never
                                   constrains the result
    empty_selector_list invalid — enforced entirely by `rule.py`'s own
                                   model validators; this module never
                                   observes an empty selector array, because
                                   `OperationAwarePolicyMatch` cannot be
                                   constructed with one

`rule.effect` and rule metadata do not affect selector evaluation
────────────────────────────────────────────────────────────────────────
This module never reads `rule.effect`, `rule.reason_code`,
`rule.explanation`, or `rule.rule_id` to determine its result. An `allow`
rule and a `deny` rule with identical `match`/`conditions` produce
identical `SelectorEvaluation` results; `rule.effect` is preserved as rule
data for a later, separately-scoped rule-aggregation stage this module
does not implement.

Purity
────────────────────────────────────────────────────────────────────────
`evaluate_rule_selectors` reads `rule` and `request` only; it never mutates
either (both are frozen Pydantic models already, and this module performs
no `model_copy`, no attribute assignment, and no reconstruction of any
kind). It performs no I/O, no network access, no clock access, and no
random-value access, and accepts only already-typed
`OperationAwarePolicyRule`/`OperationAwareDecisionRequest` models — no raw
mapping, no YAML loading, no rule or request validation is performed here
(both are expected to have already been constructed/validated before
reaching this function).

Import boundary
────────────────
This module depends on the standard library and
`basis_core.policy.operation_aware.rule.{OperationAwarePolicyMatch,
OperationAwarePolicyRule}` (PR 13, reused, not duplicated) and
`basis_core.decisions.operation_aware.OperationAwareDecisionRequest` (PR 8,
reused, not duplicated) only — the same
`basis_core.decisions.operation_aware` dependency `applicability.py` (PR
17) already established as legitimate, anticipated `policy/` precedent
(see that module's own "Import boundary" docstring section for the
documented, narrower-than-`docs/import-boundaries.md`'s-general-prose
tension this repeats, and this module's final PR report for the explicit
note that this module makes the identical, already-precedented choice, not
a new one). It does not import
`basis_core.policy.operation_aware.bundle`,
`basis_core.policy.operation_aware.applicability`,
`basis_core.policy.operation_aware.validation`,
`basis_core.policy.operation_aware.condition` (no condition evaluation is
performed, so no import of `PolicyCondition` is needed beyond what
`rule.py`'s own `OperationAwarePolicyRule.conditions` field already types),
`basis_core.policy.engine`, `basis_core.policy.rules`,
`basis_core.enforcement`, or `basis_core.audit`.

PR 20 addition — deterministic candidate-rule ordering
────────────────────────────────────────────────────────────────────────
The roadmap's PR 20 entry ("Selector determinism/ordering tests") names
only a test-file extension (`tests/operation_aware/test_selector.py`), on
the assumption that a multi-rule candidate-selection entry point already
existed. Inspection at PR 20 time found that PR 19 deliberately implements
only the single-rule `evaluate_rule_selectors` above and explicitly
disclaims "bundle iteration, candidate selection, candidate ordering, rule
sorting" as out of its scope. There was therefore no production behavior
whose ordering the roadmap-required test could exercise without the test
itself performing the sort — which would only prove the test code is
deterministic, not `basis-core`. PR 20 adds the smallest production
function that closes this gap:

  CandidateRuleEvaluation   An immutable `(rule, selector_evaluation)`
                             pairing — one already-typed
                             `OperationAwarePolicyRule` alongside the
                             `SelectorEvaluation` `evaluate_rule_selectors`
                             produced for it against one request. Carries
                             no new fields beyond that association: no
                             duplicated rule data, no ordering metadata, no
                             priority/weight/rank field.
  select_candidate_rules()   `(Iterable[OperationAwarePolicyRule],
                              OperationAwareDecisionRequest) ->
                              tuple[CandidateRuleEvaluation, ...]`. Calls
                             `evaluate_rule_selectors` once per rule
                             (unchanged, not reimplemented) and returns
                             every rule's evaluation — matched,
                             not_matched, and not_matched-with-conditions-
                             pending alike — as an immutable tuple sorted
                             by exact ascending lexical `rule.rule_id`.
                             `rule_id` is a stable deterministic
                             tie-breaker only (ADR-0002 §8; ADR-0004 §10)
                             — it is not authorization precedence, rule
                             priority, or evaluation order in any
                             normative sense; no other ordering signal
                             (input list position, dict/set iteration
                             order, `rule.effect`, selector result,
                             `conditions_pending`) affects the output.

Candidate semantics — all evaluated rules, not matched-only: ADR-0003 §5
("Rule Evaluation Evidence") requires rule-level trace evidence recording
"what happened when each candidate rule was considered," including a
`match / no-match / error` field per rule, and the roadmap's own PR 26
("Trace assembly function") is explicit that `EvaluationTrace` is
assembled "from Milestone 6's selector output" — i.e., directly from what
this function returns. A matched-only filter here would silently discard
the not_matched (and not_matched-pending-conditions) evidence a future
trace stage needs to represent honestly, so `select_candidate_rules` keeps
every rule's evaluation, filtering nothing.

`select_candidate_rules` performs no deduplication and does not detect or
reject duplicate `rule_id` values. Bundle-level `rule_id` uniqueness is
`validation.py`'s (PR 15) responsibility, already enforced upstream of
this function for any rule collection sourced from a validated
`PolicyBundle`; this function accepts a generic `Iterable` and does not
re-validate its input, so a caller that bypasses bundle validation and
supplies duplicate `rule_id` values will see both evaluations preserved,
side by side, in the sort's stable relative order — never silently merged
or overwritten (no `{rule.rule_id: rule}` dict-collapse is used anywhere
in this function).

Not implemented by this module (deferred to later, separately-scoped
roadmap PRs): condition operator registry, field-path resolution, and
condition evaluation (Milestone 7, PRs 21-23, architecture-gated);
rule-effect application, deny precedence, default deny, and any final
authorization outcome (Milestone 9, PR 27 onward); evaluation traces and
audit evidence (Milestone 8 onward).

Public API status: internal to the operation-aware package for now,
exactly like every other operation-aware module added so far. Not
re-exported from `basis_core.policy` or any other package `__init__.py`;
see `docs/public-api.md`'s "Open API questions" convention and Section 6 of
the roadmap plan for when operation-aware symbols are expected to graduate
to the stable public API (Milestone 11, PR 35).
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import Enum

from basis_core.decisions.operation_aware import OperationAwareDecisionRequest
from basis_core.policy.operation_aware.rule import (
    OperationAwarePolicyMatch,
    OperationAwarePolicyRule,
)

__all__ = [
    "CandidateRuleEvaluation",
    "SelectorEvaluation",
    "SelectorMatchResult",
    "evaluate_rule_selectors",
    "select_candidate_rules",
]


# ══════════════════════════════════════════════════════════════════════════
# Result vocabulary
# ══════════════════════════════════════════════════════════════════════════


class SelectorMatchResult(str, Enum):
    """
    The closed, two-value selector-stage result vocabulary.

    Closed to exactly `matched` / `not_matched`. This is a classification of
    whether a rule's structural `match` criteria select a request — not an
    authorization outcome. `allow`/`deny` are rule-effect concepts
    (`rule.py`'s `RuleEffect`), produced only by a future rule-aggregation
    stage this module does not implement; `not_applicable` is a bundle-
    applicability concept (`applicability.py`'s `ApplicabilityResult`), a
    distinct, earlier pipeline stage; `error`/`skipped`/`pending` are not
    selector-stage results at all — see `SelectorEvaluation` for how this
    module represents "conditions not yet evaluated" honestly, without
    inventing a third member here. See this module's docstring for the full
    boundary.
    """

    MATCHED = "matched"
    NOT_MATCHED = "not_matched"


@dataclass(frozen=True, slots=True)
class SelectorEvaluation:
    """
    The immutable result of evaluating one rule's structural `match`
    criteria against one request.

    Two fields, both required:
      result              `SelectorMatchResult.MATCHED` only when every
                           populated `match` selector category matched
                           *and* the rule carries no conditions.
                           `SelectorMatchResult.NOT_MATCHED` in every other
                           case — including when structural selectors
                           matched but conditions remain unevaluated (see
                           `conditions_pending` below).
      conditions_pending   `True` when the rule's structural selectors are
                           satisfied (or the rule has no `match` object at
                           all) but `rule.conditions` is non-empty and has
                           not been evaluated by this module. `False` in
                           every other case, including when the rule has no
                           conditions at all and when a structural selector
                           mismatch already made a match impossible
                           regardless of what any condition would have
                           evaluated to.

    This is a plain, frozen `dataclasses.dataclass` — not a Pydantic model
    — because this type is a pure in-process function result, never
    constructed from untrusted wire input, never serialized, and requires
    no field validation of its own; the two fields' own types
    (`SelectorMatchResult`, `bool`) are already closed and self-validating.
    `slots=True` keeps instances small and prevents ad hoc attribute
    assignment from outside this module. Equality and `repr` are the
    dataclass-generated field-wise forms; two `SelectorEvaluation` values
    with equal fields compare equal.

    See this module's docstring, "Condition boundary", for the full
    rationale distinguishing this two-field shape from a single three (or
    more)-value result enum.
    """

    result: SelectorMatchResult
    conditions_pending: bool


# ══════════════════════════════════════════════════════════════════════════
# Shared comparison primitives
# ══════════════════════════════════════════════════════════════════════════


def _scalar_matches(selector: Sequence[str] | None, value: str | None) -> bool:
    """The shared scalar-selector comparison rule, used by every
    scalar-valued category below (every category except `subject_roles`).

    Args:
        selector: the rule match's populated-or-absent selector array for
            one category (`None` means "no restriction"). Typed as
            `Sequence[str]` rather than `list[str]` only so this one shared
            primitive also accepts `match.operation_intents`
            (`list[Literal["read_only", "state_changing",
            "control_affecting"]] | None`) without an unsound cast — every
            member of that `Literal` union is itself a `str`, so this is a
            widening, not a weakening, of what is accepted; this function
            never mutates `selector` regardless.
        value: the request's corresponding scalar value for that same
            category (`None` means "the request carries no value for this
            category at all").

    Returns:
        `True` if this category does not constrain the match, or if it
        constrains and the request's value is exactly one of the
        selector's accepted alternatives. `False` if the selector is
        populated and the request has no value, or has a value that is
        not among the accepted alternatives. Comparison is exact-string
        membership only — no normalization, no fuzzy matching.
    """
    if selector is None:
        return True
    if value is None:
        return False
    return value in selector


def _roles_match(selector: list[str] | None, roles: list[str]) -> bool:
    """The shared `subject_roles` comparison rule — the one selector
    category whose request counterpart is itself a collection.

    Args:
        selector: the rule match's populated-or-absent `subject_roles`
            array (`None` means "no restriction").
        roles: the request's `subject_roles` list (always a list, never
            `None`, on `OperationAwareDecisionRequest` — an empty list is
            this model's own representation of "no roles supplied").

    Returns:
        `True` if `selector` is absent, or if at least one role in `roles`
        is also present in `selector` (any exact intersection). `False` if
        `selector` is populated and `roles` is empty, or shares no member
        with `selector`. Neither list is read for more than membership: no
        full-list equality, no ordering significance, no mutation of
        either input.
    """
    if selector is None:
        return True
    if not roles:
        return False
    return any(role in selector for role in roles)


# ══════════════════════════════════════════════════════════════════════════
# Per-category helpers — explicit field access, one per match selector
# ══════════════════════════════════════════════════════════════════════════


def _subject_ids_matches(
    match: OperationAwarePolicyMatch, request: OperationAwareDecisionRequest
) -> bool:
    """`request.subject_id` is a required field (never `None`)."""
    return _scalar_matches(match.subject_ids, request.subject_id)


def _subject_roles_matches(
    match: OperationAwarePolicyMatch, request: OperationAwareDecisionRequest
) -> bool:
    """See `_roles_match` — the one collection-to-collection category."""
    return _roles_match(match.subject_roles, request.subject_roles)


def _identity_sources_matches(
    match: OperationAwarePolicyMatch, request: OperationAwareDecisionRequest
) -> bool:
    return _scalar_matches(match.identity_sources, request.identity_source)


def _authority_modes_matches(
    match: OperationAwarePolicyMatch, request: OperationAwareDecisionRequest
) -> bool:
    return _scalar_matches(match.authority_modes, request.authority_mode)


def _actions_matches(
    match: OperationAwarePolicyMatch, request: OperationAwareDecisionRequest
) -> bool:
    """`request.action` is a required field (never `None`). Compared as the
    whole composite `{verb}:{domain}[:{object}]` string — no verb/domain/
    object segmentation, no prefix matching, no action hierarchy."""
    return _scalar_matches(match.actions, request.action)


def _resources_matches(
    match: OperationAwarePolicyMatch, request: OperationAwareDecisionRequest
) -> bool:
    """Independent of `resource_types` — never derived from it or
    cross-checked against it (see this module's docstring)."""
    return _scalar_matches(match.resources, request.resource)


def _resource_types_matches(
    match: OperationAwarePolicyMatch, request: OperationAwareDecisionRequest
) -> bool:
    """Independent of `resources` — never derived from parsing its type
    prefix (see this module's docstring)."""
    return _scalar_matches(match.resource_types, request.resource_type)


def _site_ids_matches(
    match: OperationAwarePolicyMatch, request: OperationAwareDecisionRequest
) -> bool:
    """`request.location` may be entirely absent; if so, the request has no
    value for this category. No site/building/zone/area hierarchy or
    parent/child inference is applied."""
    value = request.location.site_id if request.location is not None else None
    return _scalar_matches(match.site_ids, value)


def _building_ids_matches(
    match: OperationAwarePolicyMatch, request: OperationAwareDecisionRequest
) -> bool:
    """See `_site_ids_matches` for the shared location-absence handling;
    independent of site/zone/area."""
    value = request.location.building_id if request.location is not None else None
    return _scalar_matches(match.building_ids, value)


def _zone_ids_matches(
    match: OperationAwarePolicyMatch, request: OperationAwareDecisionRequest
) -> bool:
    """See `_site_ids_matches`; independent of site/building/area."""
    value = request.location.zone_id if request.location is not None else None
    return _scalar_matches(match.zone_ids, value)


def _area_ids_matches(
    match: OperationAwarePolicyMatch, request: OperationAwareDecisionRequest
) -> bool:
    """See `_site_ids_matches`; independent of site/building/zone."""
    value = request.location.area_id if request.location is not None else None
    return _scalar_matches(match.area_ids, value)


def _device_ids_matches(
    match: OperationAwarePolicyMatch, request: OperationAwareDecisionRequest
) -> bool:
    """`request.device` may be entirely absent. Never inferred from
    `resource` or protocol context."""
    value = request.device.device_id if request.device is not None else None
    return _scalar_matches(match.device_ids, value)


def _device_classes_matches(
    match: OperationAwarePolicyMatch, request: OperationAwareDecisionRequest
) -> bool:
    """See `_device_ids_matches`; independent of `device_ids`."""
    value = request.device.device_class if request.device is not None else None
    return _scalar_matches(match.device_classes, value)


def _protocols_matches(
    match: OperationAwarePolicyMatch, request: OperationAwareDecisionRequest
) -> bool:
    """`request.protocol_context` may be entirely absent. Evidence-only
    comparison — no protocol parsing, no protocol library dependency."""
    value = request.protocol_context.protocol if request.protocol_context is not None else None
    return _scalar_matches(match.protocols, value)


def _protocol_operations_matches(
    match: OperationAwarePolicyMatch, request: OperationAwareDecisionRequest
) -> bool:
    """Independent of `protocols` — never derived from it. Exact string
    comparison only: no protocol-native operation-name normalization (e.g.
    `WriteProperty` never matches `writeproperty` or `write_property`)."""
    value = request.protocol_context.operation if request.protocol_context is not None else None
    return _scalar_matches(match.protocol_operations, value)


def _operation_intents_matches(
    match: OperationAwarePolicyMatch, request: OperationAwareDecisionRequest
) -> bool:
    """`request.operation_intent` is a closed `OperationIntent` (`str`,
    `Enum`) when present. Explicit `.value` access is used (never
    `str(enum)`) to compare against `match.operation_intents`'s plain
    `str`/`Literal` alternatives without relying on `str`/`Enum`
    interoperability semantics — see this module's docstring, "Selector-to-
    request mapping"."""
    value = request.operation_intent.value if request.operation_intent is not None else None
    return _scalar_matches(match.operation_intents, value)


def _safety_modes_matches(
    match: OperationAwarePolicyMatch, request: OperationAwareDecisionRequest
) -> bool:
    """`request.safety_context` may be entirely absent. No safety-state
    inference or calculation — a supplied label only."""
    value = request.safety_context.mode if request.safety_context is not None else None
    return _scalar_matches(match.safety_modes, value)


def _safety_classifications_matches(
    match: OperationAwarePolicyMatch, request: OperationAwareDecisionRequest
) -> bool:
    """See `_safety_modes_matches`; independent of `safety_modes`."""
    value = request.safety_context.classification if request.safety_context is not None else None
    return _scalar_matches(match.safety_classifications, value)


def _environment_modes_matches(
    match: OperationAwarePolicyMatch, request: OperationAwareDecisionRequest
) -> bool:
    """`request.environment_context` may be entirely absent."""
    value = request.environment_context.mode if request.environment_context is not None else None
    return _scalar_matches(match.environment_modes, value)


def _risk_classifications_matches(
    match: OperationAwarePolicyMatch, request: OperationAwareDecisionRequest
) -> bool:
    """`request.risk_context` may be entirely absent. No risk calculation —
    a supplied classification label only, never the numeric `score`, for
    which no selector is published."""
    value = request.risk_context.classification if request.risk_context is not None else None
    return _scalar_matches(match.risk_classifications, value)


# ══════════════════════════════════════════════════════════════════════════
# Structural match combination — all-of across every populated category
# ══════════════════════════════════════════════════════════════════════════


def _all_selectors_match(
    match: OperationAwarePolicyMatch, request: OperationAwareDecisionRequest
) -> bool:
    """Every populated selector category on `match` must match `request`
    (`match_semantics.across_selectors: all_of`). `match` is guaranteed by
    `OperationAwarePolicyMatch`'s own construction-time validation to have
    at least one populated selector — this function never observes a
    `match` object with zero populated categories."""
    category_checks = (
        _subject_ids_matches(match, request),
        _subject_roles_matches(match, request),
        _identity_sources_matches(match, request),
        _authority_modes_matches(match, request),
        _actions_matches(match, request),
        _resources_matches(match, request),
        _resource_types_matches(match, request),
        _site_ids_matches(match, request),
        _building_ids_matches(match, request),
        _zone_ids_matches(match, request),
        _area_ids_matches(match, request),
        _device_ids_matches(match, request),
        _device_classes_matches(match, request),
        _protocols_matches(match, request),
        _protocol_operations_matches(match, request),
        _operation_intents_matches(match, request),
        _safety_modes_matches(match, request),
        _safety_classifications_matches(match, request),
        _environment_modes_matches(match, request),
        _risk_classifications_matches(match, request),
    )
    return all(category_checks)


# ══════════════════════════════════════════════════════════════════════════
# Public entry point
# ══════════════════════════════════════════════════════════════════════════


def evaluate_rule_selectors(
    rule: OperationAwarePolicyRule,
    request: OperationAwareDecisionRequest,
) -> SelectorEvaluation:
    """Evaluate `rule`'s structural `match` criteria against `request`,
    honestly reflecting whether any unevaluated `conditions` remain.

    A pure, deterministic classification — see this module's docstring for
    the full semantics and boundary. Does not evaluate `rule.conditions`
    in any way (Milestone 7 remains architecture-gated) and does not apply
    `rule.effect`. Assumes the caller has already established, via
    `applicability.py`'s `determine_applicability`, that this rule's
    containing bundle is applicable to `request` — this function performs
    no applicability determination of its own and does not require one to
    have run first in order to produce a correct structural-match result
    for the one rule given to it.

    Truth table (the four cases the roadmap's Section 8 condition gate
    requires):

        match criteria   conditions   result       conditions_pending
        ───────────────   ──────────   ───────────   ───────────────────
        match             absent       MATCHED       False
        mismatch          absent       NOT_MATCHED   False
        match             present      NOT_MATCHED   True
        mismatch          present      NOT_MATCHED   False

    A rule with `match is None` (and, by `OperationAwarePolicyRule`'s own
    construction-time invariant, therefore non-empty `conditions` — a rule
    with neither is not constructible) is treated as "match criteria
    trivially satisfied, conditions present": `absent_selector: no_
    restriction` extends to an entirely absent `match` object exactly as
    it does to any one populated `match`'s unpopulated selector categories,
    so this is the same "match" row above, not a fifth, special-cased
    state — it always reports `NOT_MATCHED` with `conditions_pending=True`
    (`policy-rule.md`'s conditions-only-rule reading), never `MATCHED`.

    Args:
        rule: an already-constructed `OperationAwarePolicyRule`.
        request: an already-constructed `OperationAwareDecisionRequest`.

    Returns:
        A `SelectorEvaluation`. `result` is `SelectorMatchResult.MATCHED`
        only when every populated `match` selector category matched (or
        `match` is absent entirely) *and* `rule.conditions` is empty.
        Every other case returns `SelectorMatchResult.NOT_MATCHED`, with
        `conditions_pending` distinguishing "conditions remain unevaluated
        after a full structural match" (`True`) from "a structural
        mismatch already made a match impossible, independent of what any
        condition would have evaluated to" (`False`).
    """
    if rule.match is not None and not _all_selectors_match(rule.match, request):
        return SelectorEvaluation(
            result=SelectorMatchResult.NOT_MATCHED,
            conditions_pending=False,
        )

    # Structural selectors are satisfied — either every populated category
    # on `rule.match` matched, or `rule.match` is absent entirely (no
    # restriction). Whether the result is `MATCHED` now depends only on
    # whether `rule.conditions` remains to be evaluated.
    if rule.conditions:
        return SelectorEvaluation(
            result=SelectorMatchResult.NOT_MATCHED,
            conditions_pending=True,
        )

    return SelectorEvaluation(
        result=SelectorMatchResult.MATCHED,
        conditions_pending=False,
    )


# ══════════════════════════════════════════════════════════════════════════
# Deterministic candidate-rule selection (PR 20)
# ══════════════════════════════════════════════════════════════════════════


@dataclass(frozen=True, slots=True)
class CandidateRuleEvaluation:
    """
    An immutable association between one already-typed
    `OperationAwarePolicyRule` and the `SelectorEvaluation`
    `evaluate_rule_selectors` produced for it against one request.

    This is the unit `select_candidate_rules` returns, one per input rule.
    It duplicates no rule field: `rule` is the same object the caller
    supplied (never copied, reconstructed, or partially re-serialized),
    and `selector_evaluation` is exactly what `evaluate_rule_selectors`
    already returned for that rule — this type adds no new matching,
    ordering, effect, or outcome semantics of its own. See this module's
    docstring, "PR 20 addition", for the full rationale, including why
    candidate output preserves every evaluated rule rather than
    matched-only rules.

    A plain, frozen `dataclasses.dataclass` — not a Pydantic model — for
    the same reason `SelectorEvaluation` is one: a pure in-process function
    result, never constructed from untrusted wire input, never serialized,
    requiring no field validation beyond what `rule`
    (`OperationAwarePolicyRule`) and `selector_evaluation`
    (`SelectorEvaluation`) already enforce on their own construction.
    """

    rule: OperationAwarePolicyRule
    selector_evaluation: SelectorEvaluation


def select_candidate_rules(
    rules: Iterable[OperationAwarePolicyRule],
    request: OperationAwareDecisionRequest,
) -> tuple[CandidateRuleEvaluation, ...]:
    """
    Evaluate every rule in `rules` against `request` and return the result
    as an immutable, deterministically ordered tuple of
    `CandidateRuleEvaluation`.

    Ordering: the returned tuple is sorted by exact ascending lexical
    `rule.rule_id` — the stable, deterministic tie-breaker ADR-0002 §8 and
    ADR-0004 §10 both name for when no other ordering signal is defined.
    `rule_id` ordering here is a determinism guarantee only; it carries no
    authorization precedence, priority, or evaluation-order meaning. Input
    list position, dict/set iteration order used to construct `rules`,
    `rule.effect`, the resulting `SelectorEvaluation.result`, and
    `SelectorEvaluation.conditions_pending` never affect this output order
    — see this module's docstring, "PR 20 addition", and this function's
    final PR report for the determinism coverage this guarantees.

    Filtering: none. Every rule in `rules` is evaluated and included in the
    output, whether its selector evaluation is `matched`, `not_matched`, or
    `not_matched` with `conditions_pending=True` — see "PR 20 addition" for
    why matched-only filtering would be an unsupported, silently invented
    semantic.

    Duplicates: this function performs no deduplication and does not
    detect or reject duplicate `rule_id` values in `rules`. Bundle-level
    `rule_id` uniqueness is `validation.py`'s (PR 15) responsibility; this
    function trusts that a rule collection sourced from an already-
    validated `PolicyBundle` is already unique and does not re-check it. A
    caller that supplies duplicate `rule_id` values directly (bypassing
    bundle validation) will see every one of them preserved in the output,
    in the sort's stable relative order — never collapsed via a
    `{rule.rule_id: rule}`-shaped mapping, which could otherwise silently
    hide a duplicate by letting one overwrite another.

    Purity: reads `rules` and `request` only. Does not mutate `rules` (nor
    any rule within it), `request`, or any nested request context object;
    does not sort a caller-owned list in place (`sorted()` always returns a
    new list, and this function always returns a new tuple built from it).
    Performs no I/O, no network access, no clock access, and no
    random-value access.

    Args:
        rules: any iterable of already-typed, already-validated
            `OperationAwarePolicyRule` instances — a `list`, a `tuple`, a
            generator over a `dict`'s values, a set-derived sequence, or a
            `PolicyBundle.rules` array. Never mutated; consumed at most
            once regardless of iterable type.
        request: an already-constructed `OperationAwareDecisionRequest`.

    Returns:
        A `tuple[CandidateRuleEvaluation, ...]`, one entry per rule in
        `rules`, sorted by `rule.rule_id` ascending. Empty if `rules` is
        empty. A single-element tuple if `rules` has exactly one rule.
    """
    evaluations = tuple(
        CandidateRuleEvaluation(
            rule=rule,
            selector_evaluation=evaluate_rule_selectors(rule, request),
        )
        for rule in rules
    )
    return tuple(
        sorted(
            evaluations,
            key=lambda candidate: candidate.rule.rule_id,
        )
    )
