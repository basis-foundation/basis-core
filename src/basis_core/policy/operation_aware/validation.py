"""
basis_core.policy.operation_aware.validation — the explicit `PolicyBundle`
structural/semantic validation pipeline.

This module is the fourth module added under `src/basis_core/policy/
operation_aware/` for `basis-core` v0.2.0 (see
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`, Milestone 4,
PR 15 — "Policy bundle structural + semantic validation pipeline"), after
PR 12's `condition.py`, PR 13's `rule.py`, and PR 14's `bundle.py`. It
implements the one piece of `policy-bundle`'s published contract that
`bundle.py` deliberately left unenforced (see `bundle.py`'s docstring,
"Deferred to PR 15"): bundle-level `rule_id` uniqueness across
`PolicyBundle.rules`, plus an explicit, pipeline-owned statement of
rule-level `condition_id` uniqueness (`policy-bundle.md` §18; ADR-0004 §11;
ADR-0002 §14).

  validate_policy_bundle()   The single public entry point. Accepts either
                              raw serialized policy data (a mapping) or an
                              already-constructed `PolicyBundle`, runs
                              structural validation (if needed) followed by
                              deterministic, ordered semantic checks, and
                              returns a validated `PolicyBundle` — or raises
                              a `PolicyBundleValidationError` subclass.

Why this module exists, and what it makes true by construction
────────────────────────────────────────────────────────────────────────
No `evaluate()` entry point or orchestrating evaluator exists anywhere in
this repository yet — there is no `OperationAwareEvaluationEngine`, and no
code path that accepts raw, unvalidated policy data and turns it into an
authorization decision. This module's entire purpose is to exist *before*
one does, so that the invariant

    invalid policy → validation failure → never reaches evaluation
                                          → can never produce ALLOW

is true by construction from the moment evaluation is added: PR 27's
policy-owned aggregation logic (`aggregation.py`) and the future
evaluation-owned orchestrator, `OperationAwareEvaluationEngine` (PR 27B),
can each only be wired to accept a `PolicyBundle` that has already passed
through `validate_policy_bundle`, and this module guarantees that a bundle
failing either the structural or the semantic checks below never becomes
that accepted `PolicyBundle` value in the first place.

Architectural boundary — validation only, no evaluation
────────────────────────────────────────────────────────────────────────
This module does not implement, and must never grow: `evaluate()`,
`PolicyEngine`, rule matching, condition execution, selector matching,
scope applicability, deny precedence, default-deny, "not applicable"
determination, trace generation, decision-response assembly, audit
evidence, or gateway enforcement. It ends with a validated `PolicyBundle`
returned to its caller — never an authorization result. Scope-to-request
applicability (PR 17), policy-owned effect aggregation (`aggregation.py`,
PR 27), and the future evaluation-owned orchestrator,
`OperationAwareEvaluationEngine` (PR 27B), are later, separately-scoped
roadmap work relative to this module.

Two failure categories, one root
────────────────────────────────────────────────────────────────────────
`PolicyBundleValidationError` is the root of a small, deliberately shallow
hierarchy:

  StructuralPolicyValidationError
      Raised when the input's *shape* is malformed — missing fields, wrong
      types, invalid patterns, invalid nested structures — anything a
      single `PolicyBundle.model_validate(...)` call alone already
      rejects. This module does not re-implement any of that checking; it
      only wraps the `pydantic.ValidationError` `PolicyBundle`'s own
      field/model validators raise, preserving it as `__cause__`.
  SemanticPolicyValidationError
      Raised when the input is structurally well-formed (a `PolicyBundle`
      already exists) but its *combined meaning* violates a cross-object
      policy-level invariant Pydantic's single-model validators cannot
      express on their own: duplicate `rule_id` values across
      `bundle.rules`, and duplicate `condition_id` values within one
      rule's `conditions`. `DuplicateRuleIdError` and
      `DuplicateConditionIdError` are its two named subclasses — added
      because they materially improve the clarity of what went wrong, not
      because this module is building out a broad, speculative catalog of
      future semantic-error subclasses.

Validation ordering and fail-fast policy
────────────────────────────────────────────────────────────────────────
`validate_policy_bundle` runs, in this fixed order: (1) structural
validation/construction, (2) bundle-level duplicate-`rule_id` detection,
(3) rule-level duplicate-`condition_id` detection. Each stage raises on
its *first* detected violation, in authored (list) order — this module
does not aggregate multiple errors into one report, does not add
warnings, severities, or a diagnostics catalog, and does not rely on set
or dict iteration order for anything user-visible (duplicate detection
walks `bundle.rules`/`rule.conditions` in their own authored order, using
a `set` purely as a "seen" membership check, never as a source of
reported ordering). The same bundle always produces the same error type,
on the same duplicate identifier, with the same message.

Duplicate `rule_id`: exact-string comparison, first-duplicate-wins
────────────────────────────────────────────────────────────────────────
Comparison is exact-string equality only — no lowercasing, trimming,
normalization, canonicalization, deduplication, or "keep the first/last
rule" behavior of any kind. `_validate_unique_rule_ids` raises
`DuplicateRuleIdError` identifying `bundle.bundle_id` and the duplicate
`rule_id` (not the entire bundle) as soon as it encounters a `rule_id` it
has already seen, walking `bundle.rules` in authored order.

Duplicate `condition_id`: PR 13 already blocks this structurally — the
central ambiguity this module resolves explicitly
────────────────────────────────────────────────────────────────────────
`rule.py`'s `OperationAwarePolicyRule` already carries a rule-owned
`model_validator(mode="after")`
(`_check_condition_id_uniqueness`, PR 13) that rejects a rule constructed
— via ordinary `__init__`/`model_validate` — with duplicate
`condition_id` values in its `conditions` array. That check was correct
and intentional for PR 13's own scope (the rule owns its `conditions`
array; a standalone `PolicyCondition` has no sibling conditions to
compare against). It has two direct consequences for this module, which
this module does not paper over:

  1. Mapping input: a raw mapping whose `rules[i].conditions` contains a
     duplicate `condition_id` fails inside `PolicyBundle.model_validate`
     itself — this module's *structural* stage — before any semantic
     check below could ever run. `validate_policy_bundle` on such input
     raises `StructuralPolicyValidationError` (with the underlying
     `pydantic.ValidationError`, itself carrying PR 13's own
     `_check_condition_id_uniqueness` message, preserved as `__cause__`),
     not `SemanticPolicyValidationError`. This is not a bug in this
     module; it is PR 13's own, earlier, already-shipped enforcement of
     the same invariant at a different layer.
  2. Typed `PolicyBundle` input: because `OperationAwarePolicyRule`'s
     ordinary constructor path can never produce a rule with duplicate
     `condition_id` values, no legitimately-constructed `PolicyBundle`
     can exhibit the violation `_validate_unique_condition_ids` checks
     for either. Calling `validate_policy_bundle` with a bundle built the
     ordinary way therefore can never reach the `DuplicateConditionIdError`
     branch of this module's own code.

This module still implements `_validate_unique_condition_ids` explicitly,
as production code, as PR 15's own required, roadmap-mandated statement of
the invariant at the bundle-validation-pipeline layer (`policy-bundle.md`
§18; ADR-0004 §11) — not merely a comment pointing at `rule.py`. Two
reasons this is the correct call, not redundant dead code: first, it is
defense-in-depth — if a future change ever relaxed PR 13's
constructor-level check (deliberately or by accident), this pipeline would
still catch the violation at the one place every future evaluation entry
point is required to route through; second, `policy-bundle.md` §18
assigns bundle-level condition_id-uniqueness enforcement to the explicit
validation pipeline, not to any one nested model's own validator, as an
architectural statement independent of what any single model happens to
already enforce. This module does **not** weaken, remove, or duplicate
PR 13's own `rule.py` check to "give itself something to catch" — doing
that would be exactly the kind of pipeline-ownership faking this module
must avoid.

`tests/operation_aware/test_policy_validation.py` demonstrates
`_validate_unique_condition_ids` genuinely executing and raising
`DuplicateConditionIdError` — without touching, weakening, or bypassing
`rule.py`'s own validator for any ordinary caller — by using
`OperationAwarePolicyRule.model_construct(...)`/
`PolicyBundle.model_construct(...)` (pydantic's own, public,
"already-validated data" construction path, which intentionally skips
field/model validators) to build a real, correctly-typed `PolicyBundle`
whose one rule carries two real `PolicyCondition` instances sharing a
`condition_id`. Passing that typed bundle into `validate_policy_bundle`
takes the "already a `PolicyBundle`" branch of the structural stage (no
re-validation), so `_validate_unique_condition_ids` runs for real and
raises. This is the most honest available demonstration that this
module — not `rule.py` — owns the bundle-validation-pipeline statement of
this invariant, given that `rule.py`'s own constructor path can never be
used to build the violating case in the first place. See that test
module's docstring for the full picture, including the mapping-input case
that shows `StructuralPolicyValidationError` firing first, exactly as
described above.

No stored validation state
────────────────────────────────────────────────────────────────────────
`validate_policy_bundle` returns a valid `PolicyBundle` or raises; it
never returns `None`, never returns a `bool`, never mutates its input, and
never adds or sets any field (`validation_status`, `is_valid`, `validated`,
`validation_errors`, `validated_at`, or anything else) on the bundle it
returns. Validation is derived process state, not stored data — see
`bundle.py`'s own docstring for why `PolicyBundle` itself carries no such
field.

Import boundary
────────────────
This module depends on the standard library, `pydantic` (only
`pydantic.ValidationError`, to catch the exception `PolicyBundle` itself
raises), and `basis_core.policy.operation_aware.bundle.PolicyBundle`
(PR 14, reused, not duplicated) only. It does not import
`basis_core.decisions`, `basis_core.enforcement`, `basis_core.audit`,
`basis_core.adapters`, `basis_core.policy.engine`, or
`basis_core.policy.rules`. It performs no network, filesystem,
environment, clock, or random access, and does no YAML parsing of any
kind — it receives already-loaded mappings or already-constructed
`PolicyBundle` instances from its caller.

Public API status: internal to the operation-aware package for now,
exactly like `condition.py` (PR 12), `rule.py` (PR 13), and `bundle.py`
(PR 14). Not re-exported from `basis_core.policy` or any other package
`__init__.py`; see `docs/public-api.md`'s "Open API questions" convention
and Section 6 of the roadmap plan for when operation-aware symbols are
expected to graduate to the stable public API (Milestone 11, PR 35).
"""

from __future__ import annotations

from collections.abc import Mapping

from pydantic import ValidationError

from basis_core.policy.operation_aware.bundle import PolicyBundle

__all__ = [
    "DuplicateConditionIdError",
    "DuplicateRuleIdError",
    "PolicyBundleValidationError",
    "SemanticPolicyValidationError",
    "StructuralPolicyValidationError",
    "validate_policy_bundle",
]


# ══════════════════════════════════════════════════════════════════════════
# Error hierarchy
# ══════════════════════════════════════════════════════════════════════════


class PolicyBundleValidationError(Exception):
    """Root of the `PolicyBundle` validation error hierarchy.

    Never raised directly — always raised as one of the two subclasses
    below (or one of their own narrower subclasses). Callers that only
    need to know "did validation fail" without distinguishing structural
    from semantic failure may catch this root type; callers that need the
    distinction should catch the specific subclass.
    """


class StructuralPolicyValidationError(PolicyBundleValidationError):
    """The input's shape is malformed at the Pydantic-construction
    boundary: missing required fields, wrong field types, a value that
    fails a field pattern, or an invalid nested structure (a malformed
    rule, condition, or scope). Always carries the original
    `pydantic.ValidationError` `PolicyBundle.model_validate` raised as
    `__cause__` — never swallowed, never re-worded away."""


class SemanticPolicyValidationError(PolicyBundleValidationError):
    """The input is structurally well-formed — a `PolicyBundle` already
    exists — but its combined meaning violates a cross-object policy-level
    invariant that no single model's own Pydantic validators can express
    in isolation. See `DuplicateRuleIdError` and `DuplicateConditionIdError`
    for this module's two concrete cases."""


class DuplicateRuleIdError(SemanticPolicyValidationError):
    """`bundle.rules` contains two or more rules sharing the same
    `rule_id`. Comparison is exact-string, with no normalization; see this
    module's docstring, "Duplicate `rule_id`"."""


class DuplicateConditionIdError(SemanticPolicyValidationError):
    """One rule's `conditions` array contains two or more conditions
    sharing the same `condition_id`. See this module's docstring,
    "Duplicate `condition_id`", for why this is provably unreachable
    through this module's mapping-input path today (PR 13 already blocks
    it earlier, structurally) and how this module's own test suite still
    demonstrates this check executing for real."""


# ══════════════════════════════════════════════════════════════════════════
# Public entry point
# ══════════════════════════════════════════════════════════════════════════


def validate_policy_bundle(value: PolicyBundle | Mapping[str, object]) -> PolicyBundle:
    """Validate `value` as a `PolicyBundle`, structurally and semantically.

    Args:
        value: either raw serialized policy data (any `Mapping`, e.g. a
            `dict` freshly parsed from JSON/YAML) or an already-constructed
            `PolicyBundle`.

    Returns:
        A validated `PolicyBundle`. If `value` was already a `PolicyBundle`
        and passes every semantic check, the same instance is returned
        (no unnecessary serialize/reconstruct round trip). Neither `value`
        nor any object it references is mutated by this call.

    Raises:
        StructuralPolicyValidationError: `value` is a mapping that
            `PolicyBundle.model_validate` rejects (malformed shape). The
            original `pydantic.ValidationError` is preserved as
            `__cause__`. Also raised if `value` is neither a `PolicyBundle`
            nor a `Mapping`.
        DuplicateRuleIdError: `value` (or its structurally-validated form)
            contains two or more rules sharing one `rule_id`.
        DuplicateConditionIdError: one rule contains two or more conditions
            sharing one `condition_id`.

    This function never returns `None`, never returns a `bool`, and never
    silently repairs, mutates, or stores validation state on the bundle it
    returns — see this module's docstring, "No stored validation state".
    """
    bundle = _validate_structure(value)
    _validate_unique_rule_ids(bundle)
    _validate_unique_condition_ids(bundle)
    return bundle


# ══════════════════════════════════════════════════════════════════════════
# Structural stage
# ══════════════════════════════════════════════════════════════════════════


def _validate_structure(value: PolicyBundle | Mapping[str, object]) -> PolicyBundle:
    """Resolve `value` to a `PolicyBundle`, raising
    `StructuralPolicyValidationError` on malformed input.

    An already-constructed `PolicyBundle` is returned unchanged — its
    structural construction is already complete, and this module does not
    serialize and reconstruct a typed bundle unnecessarily. A `Mapping` is
    passed to `PolicyBundle.model_validate` unchanged (no defensive copy is
    needed: this module never writes to `value`, and `model_validate` does
    not mutate its input); a resulting `pydantic.ValidationError` is
    wrapped, with its message describing only that structural validation
    failed — never the raw, potentially sensitive, input content — and the
    original exception preserved as `__cause__`.
    """
    if isinstance(value, PolicyBundle):
        return value
    if isinstance(value, Mapping):
        try:
            return PolicyBundle.model_validate(value)
        except ValidationError as exc:
            raise StructuralPolicyValidationError(
                "Structural policy-bundle validation failed: the supplied mapping does "
                "not match the PolicyBundle contract shape. See __cause__ for the "
                "underlying pydantic.ValidationError."
            ) from exc
    raise StructuralPolicyValidationError(
        "Structural policy-bundle validation failed: expected a PolicyBundle instance "
        f"or a Mapping, got {type(value).__name__}."
    )


# ══════════════════════════════════════════════════════════════════════════
# Semantic stage
# ══════════════════════════════════════════════════════════════════════════


def _validate_unique_rule_ids(bundle: PolicyBundle) -> None:
    """Raise `DuplicateRuleIdError` on the first `rule_id` repeated across
    `bundle.rules`, walked in authored order. Exact-string comparison
    only — see this module's docstring, "Duplicate `rule_id`"."""
    seen: set[str] = set()
    for rule in bundle.rules:
        if rule.rule_id in seen:
            raise DuplicateRuleIdError(
                f"PolicyBundle {bundle.bundle_id!r} contains a duplicate rule_id "
                f"{rule.rule_id!r}; rule_id values must be unique across bundle.rules."
            )
        seen.add(rule.rule_id)


def _validate_unique_condition_ids(bundle: PolicyBundle) -> None:
    """Raise `DuplicateConditionIdError` on the first `condition_id`
    repeated within one rule's `conditions`, walked in authored order.
    Uniqueness is scoped to one rule at a time — the same `condition_id`
    appearing in two different rules' `conditions` arrays is not a
    violation (a fresh `seen` set is started for each rule). See this
    module's docstring, "Duplicate `condition_id`", for why this check is
    provably unreachable through this module's mapping-input path today."""
    for rule in bundle.rules:
        seen: set[str] = set()
        for condition in rule.conditions or ():
            if condition.condition_id in seen:
                raise DuplicateConditionIdError(
                    f"PolicyBundle {bundle.bundle_id!r} rule {rule.rule_id!r} contains a "
                    f"duplicate condition_id {condition.condition_id!r}; condition_id "
                    "values must be unique within one rule's conditions."
                )
            seen.add(condition.condition_id)
