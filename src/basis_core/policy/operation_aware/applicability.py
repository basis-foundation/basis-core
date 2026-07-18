"""
basis_core.policy.operation_aware.applicability — bundle scope applicability
determination.

This module is the fifth module added under `src/basis_core/policy/
operation_aware/` for `basis-core` v0.2.0 (see
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`, Milestone 5,
PR 17 — "Bundle scope model + applicability determination"), after PR 12's
`condition.py`, PR 13's `rule.py`, PR 14's `bundle.py`, and PR 15's
`validation.py`. It implements the one deterministic classification PR 14's
`bundle.py` deliberately left unimplemented (see that module's docstring,
"Scope semantics boundary"): whether a validated `PolicyBundle`'s optional
`scope` applies to a given `OperationAwareDecisionRequest` at all.

  determine_applicability()   The single public entry point. A pure
                               function: `(PolicyBundle,
                               OperationAwareDecisionRequest) ->
                               ApplicabilityResult`.
  ApplicabilityResult         The closed, two-value applicability
                               vocabulary (`applicable` / `not_applicable`).

Architectural boundary — applicability only, no evaluation
────────────────────────────────────────────────────────────────────────
This module answers exactly one question: does this bundle's declared
scope cover this request? It does not implement, and must never grow:
rule iteration, candidate-rule selection, `OperationAwarePolicyMatch`
evaluation, condition evaluation, rule effects, deny precedence,
default-deny, a final authorization outcome, evaluation traces, decision
responses, audit evidence, or any gateway/enforcement behavior. See
`docs/architecture/operation-aware-policy-rule-model.md` §3 (`basis-
architecture`, ADR-0004 §3) for the conceptual scope model this module
implements, and `docs/architecture/operation-aware-evaluation-semantics.md`
§5 (ADR-0002 §5) for why the `NOT_APPLICABLE` distinction this module
feeds matters. This module returns `applicable`/`not_applicable` only —
never a `DecisionResponse`, never `ALLOW`/`DENY`, and this module's
`not_applicable` is never converted to `deny` here or by any caller of
this module.

Exact-match only — a conservative, explicitly-flagged first implementation
────────────────────────────────────────────────────────────────────────
Every populated `PolicyBundleScope` selector is compared against its
request counterpart using exact equality (scalar fields) or exact
membership (the request's scalar value must appear in the selector's
array of accepted alternatives). No prefix matching, suffix matching,
substring matching, glob matching, regex matching, wildcard matching, or
location/topology hierarchy inference (site → building → zone → area, or
the reverse) is implemented. This is the roadmap's own conservative
reading, not a permanent ceiling — richer scope matching is named
explicitly (Section 15 of the roadmap plan; `basis-architecture`'s
compatibility-mapping table) as a follow-up requiring its own
architectural review, not something to add informally here.

No normalization is performed by this module beyond what the typed
models already guarantee at construction time: no lowercasing,
uppercasing, trimming, aliasing, synonym mapping, or fuzzy matching. Two
values are either identical strings or they do not match.

No separate "domain" selector
────────────────────────────────────────────────────────────────────────
The vendored `policy-bundle` contract publishes no separate `domain`
selector (see `bundle.py`'s `PolicyBundleScope` and the vendored
`policy-bundle.yaml`'s `scope_shape` comment): "domain-level scoping is
expressed through the `actions` selector's domain segment or the
`resource_types` selector." This module therefore does not parse
`request.action` into `{verb}:{domain}[:{object}]` components or derive
a domain value from any other field — `scope.actions` is compared against
`request.action` as one whole composite string, exactly as published.

Ten scope dimensions, ten request counterparts
────────────────────────────────────────────────────────────────────────
    PolicyBundleScope field   Request counterpart
    ────────────────────────  ─────────────────────────────────────────
    actions                   request.action
    resource_types            request.resource_type
    site_ids                  request.location.site_id
    building_ids               request.location.building_id
    zone_ids                   request.location.zone_id
    area_ids                   request.location.area_id
    device_classes              request.device.device_class
    environment_modes           request.environment_context.mode
    authority_modes              request.authority_mode
    protocols                   request.protocol_context.protocol

Each dimension has its own small, explicitly named helper function below
— direct field access only, no `getattr` chains, no dynamic dotted-path
evaluation, no generic extension-dictionary walking, no reflection. Every
helper shares one tiny, pure comparison primitive (`_selector_matches`)
that expresses the one repeated rule: an absent selector imposes no
restriction; a populated selector requires the request's corresponding
scalar value to be a member of the selector's array, and a request that
has no value at all for that dimension (either the nested context object
itself is absent, or the object is present but the specific field is
`None`) cannot satisfy a populated selector.

Applicability semantics (per ADR-0004 §3 / `policy-bundle.yaml`'s
`scope_semantics`)
────────────────────────────────────────────────────────────────────────
  bundle.scope is None                    -> applicable (no rules
                                              inspected; every dimension
                                              is unconstrained)
  scope dimension absent (selector field
  is None)                                -> that dimension imposes no
                                              restriction
  scope dimension populated, request
  provides a matching value                -> that dimension is satisfied
  scope dimension populated, request
  provides a non-matching value            -> not_applicable
  scope dimension populated, request has
  no value for that dimension at all       -> not_applicable (a missing
                                              request counterpart can
                                              never satisfy a populated
                                              selector; it is never
                                              treated as a wildcard, and
                                              nothing is inferred,
                                              defaulted, or fetched)
  all populated dimensions match           -> applicable
  any populated dimension does not match   -> not_applicable

Purity
────────────────────────────────────────────────────────────────────────
`determine_applicability` reads `bundle` and `request` only; it never
mutates either (both are frozen Pydantic models already, and this module
performs no `model_copy`, no attribute assignment, and no reconstruction
of any kind). It performs no I/O, no network access, no clock access, and
no random-value access, and it accepts only the already-typed
`PolicyBundle`/`OperationAwareDecisionRequest` models — no raw mapping,
no YAML loading, no structural or semantic bundle validation is performed
here (that is PR 15's `validate_policy_bundle`, expected to have already
run before a bundle reaches this function).

Import boundary
────────────────
This module depends on the standard library and
`basis_core.policy.operation_aware.bundle.{PolicyBundle, PolicyBundleScope}`
(PR 14, reused, not duplicated) and
`basis_core.decisions.operation_aware.OperationAwareDecisionRequest` (PR 8,
reused, not duplicated) only. It does not import
`basis_core.policy.operation_aware.rule`,
`basis_core.policy.operation_aware.condition`,
`basis_core.policy.operation_aware.validation`, `basis_core.policy.engine`,
`basis_core.policy.rules`, `basis_core.enforcement`, or `basis_core.audit`.

Not implemented by this module (deferred to later, separately-scoped
roadmap PRs): exhaustive per-dimension and combined-dimension Cartesian
test coverage (PR 18, extends this module's own test file, not this
module itself); rule match-criteria evaluation (`selector.py`, PR 19);
condition evaluation (Milestone 7, gated); policy-owned effect aggregation
and any final authorization outcome (`aggregation.py`, PR 27); and the
future evaluation-owned orchestrator, `OperationAwareEvaluationEngine`
(PR 27B).

Public API status: internal to the operation-aware package for now,
exactly like `condition.py` (PR 12), `rule.py` (PR 13), `bundle.py`
(PR 14), and `validation.py` (PR 15). Not re-exported from
`basis_core.policy` or any other package `__init__.py`; see
`docs/public-api.md`'s "Open API questions" convention and Section 6 of
the roadmap plan for when operation-aware symbols are expected to
graduate to the stable public API (Milestone 11, PR 35).
"""

from __future__ import annotations

from enum import Enum

from basis_core.decisions.operation_aware import OperationAwareDecisionRequest
from basis_core.policy.operation_aware.bundle import PolicyBundle, PolicyBundleScope

__all__ = [
    "ApplicabilityResult",
    "determine_applicability",
]


# ══════════════════════════════════════════════════════════════════════════
# Result vocabulary
# ══════════════════════════════════════════════════════════════════════════


class ApplicabilityResult(str, Enum):
    """
    The closed, two-value bundle-applicability vocabulary.

    Closed to exactly `applicable` / `not_applicable`. This is a
    classification of whether a bundle's declared scope covers a request
    — not an authorization outcome. `ALLOW`/`DENY` are rule-effect
    concepts (`rule.py`'s `RuleEffect`), produced only by a future rule
    evaluator; `failed`/`error`/`unknown`/`indeterminate` are not
    applicability states at all — bundle/request validation failure is
    handled entirely upstream of this module (PR 15's
    `validate_policy_bundle`, and `OperationAwareDecisionRequest`'s own
    construction-time validation), never represented as a third
    applicability value here. See this module's docstring for the full
    boundary.
    """

    APPLICABLE = "applicable"
    NOT_APPLICABLE = "not_applicable"


# ══════════════════════════════════════════════════════════════════════════
# Shared comparison primitive
# ══════════════════════════════════════════════════════════════════════════


def _selector_matches(selector: list[str] | None, value: str | None) -> bool:
    """The one applicability-comparison rule, shared by every dimension
    helper below.

    Args:
        selector: the bundle scope's populated-or-absent selector array
            for one dimension (`None` means "no restriction").
        value: the request's corresponding scalar value for that same
            dimension (`None` means "the request carries no value for
            this dimension at all").

    Returns:
        `True` if this dimension does not constrain applicability, or if
        it constrains and the request's value is exactly one of the
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


# ══════════════════════════════════════════════════════════════════════════
# Per-dimension helpers — explicit field access, one per scope selector
# ══════════════════════════════════════════════════════════════════════════


def _actions_applicable(scope: PolicyBundleScope, request: OperationAwareDecisionRequest) -> bool:
    """Action-vocabulary scope. `request.action` is a required field (never
    `None`); compared as the whole composite `{verb}:{domain}[:{object}]`
    string against `scope.actions` — no domain segment is parsed out. See
    this module's docstring, "No separate 'domain' selector"."""
    return _selector_matches(scope.actions, request.action)


def _resource_types_applicable(
    scope: PolicyBundleScope, request: OperationAwareDecisionRequest
) -> bool:
    """Resource-type scope. Compared only against `request.resource_type`
    — never derived from `request.resource`'s embedded type prefix."""
    return _selector_matches(scope.resource_types, request.resource_type)


def _site_ids_applicable(scope: PolicyBundleScope, request: OperationAwareDecisionRequest) -> bool:
    """Site scope. `request.location` may be entirely absent; if so, the
    request has no value for this dimension. No site/building/zone/area
    hierarchy or parent/child inference is applied."""
    value = request.location.site_id if request.location is not None else None
    return _selector_matches(scope.site_ids, value)


def _building_ids_applicable(
    scope: PolicyBundleScope, request: OperationAwareDecisionRequest
) -> bool:
    """Building scope. See `_site_ids_applicable` for the shared
    location-absence handling; independent of site/zone/area scope."""
    value = request.location.building_id if request.location is not None else None
    return _selector_matches(scope.building_ids, value)


def _zone_ids_applicable(scope: PolicyBundleScope, request: OperationAwareDecisionRequest) -> bool:
    """Zone scope. See `_site_ids_applicable`; independent of
    site/building/area scope."""
    value = request.location.zone_id if request.location is not None else None
    return _selector_matches(scope.zone_ids, value)


def _area_ids_applicable(scope: PolicyBundleScope, request: OperationAwareDecisionRequest) -> bool:
    """Area scope. See `_site_ids_applicable`; independent of
    site/building/zone scope."""
    value = request.location.area_id if request.location is not None else None
    return _selector_matches(scope.area_ids, value)


def _device_classes_applicable(
    scope: PolicyBundleScope, request: OperationAwareDecisionRequest
) -> bool:
    """Device-class scope. `request.device` may be entirely absent. Never
    inferred from `device_id`, `resource`, or protocol context."""
    value = request.device.device_class if request.device is not None else None
    return _selector_matches(scope.device_classes, value)


def _environment_modes_applicable(
    scope: PolicyBundleScope, request: OperationAwareDecisionRequest
) -> bool:
    """Environment/deployment scope. Compared against
    `request.environment_context.mode` only — never `safety_context`,
    `risk_context`, or an OS/deployment environment variable."""
    value = request.environment_context.mode if request.environment_context is not None else None
    return _selector_matches(scope.environment_modes, value)


def _authority_modes_applicable(
    scope: PolicyBundleScope, request: OperationAwareDecisionRequest
) -> bool:
    """Identity authority-mode scope. Compared against the request's own
    normalized `authority_mode` only — never inferred from
    `identity_source` or `identity_evidence_reference`, never used to
    authenticate or verify identity."""
    return _selector_matches(scope.authority_modes, request.authority_mode)


def _protocols_applicable(scope: PolicyBundleScope, request: OperationAwareDecisionRequest) -> bool:
    """Protocol scope. `request.protocol_context` may be entirely absent.
    Evidence-only comparison — this module implements no protocol
    parsing and does not become protocol-aware by comparing this field."""
    value = request.protocol_context.protocol if request.protocol_context is not None else None
    return _selector_matches(scope.protocols, value)


# ══════════════════════════════════════════════════════════════════════════
# Public entry point
# ══════════════════════════════════════════════════════════════════════════


def determine_applicability(
    bundle: PolicyBundle,
    request: OperationAwareDecisionRequest,
) -> ApplicabilityResult:
    """Determine whether `bundle`'s declared scope applies to `request`.

    A pure, deterministic classification — see this module's docstring
    for the full semantics and boundary. Does not evaluate `bundle.rules`
    in any way: an `applicable` result means only that scope does not
    exclude this request, not that any rule inside the bundle will
    match, allow, or deny it.

    Args:
        bundle: an already-validated `PolicyBundle` (PR 15's
            `validate_policy_bundle` is expected to have already run;
            this function performs no bundle validation of its own).
        request: an already-constructed `OperationAwareDecisionRequest`.

    Returns:
        `ApplicabilityResult.APPLICABLE` if `bundle.scope` is `None`, or
        every populated scope selector matches its request counterpart.
        `ApplicabilityResult.NOT_APPLICABLE` if any populated scope
        selector does not match (including when the request carries no
        value at all for that dimension).
    """
    scope = bundle.scope
    if scope is None:
        return ApplicabilityResult.APPLICABLE

    dimension_checks = (
        _actions_applicable(scope, request),
        _resource_types_applicable(scope, request),
        _site_ids_applicable(scope, request),
        _building_ids_applicable(scope, request),
        _zone_ids_applicable(scope, request),
        _area_ids_applicable(scope, request),
        _device_classes_applicable(scope, request),
        _environment_modes_applicable(scope, request),
        _authority_modes_applicable(scope, request),
        _protocols_applicable(scope, request),
    )

    if all(dimension_checks):
        return ApplicabilityResult.APPLICABLE
    return ApplicabilityResult.NOT_APPLICABLE
