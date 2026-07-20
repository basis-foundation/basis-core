"""
tests/operation_aware/test_engine_canonical_shapes.py — canonical-shaped
unit tests for the real `OperationAwareEvaluationEngine` (Milestone 9,
PR 28 of `docs/implementation/basis-core-v0.2-operation-aware-plan.md`:
"Canonical-shaped evaluation-engine unit tests").

Objective
─────────
Prove that the real, unmocked `OperationAwareEvaluationEngine` produces the
correct *logical* result for the five canonical operation-aware
authorization scenarios published by `basis-schemas` v0.2.1's compatibility
vectors (`tests/fixtures/basis-schemas/v0.2.1/compatibility/*/`):

    allow-basic
    deny-precedence
    default-deny
    not-applicable
    invalid-policy-bundle

Every request, rule, match, scope, and bundle below is constructed directly
through the real typed Pydantic models this repository already ships
(`OperationAwareDecisionRequest`, `OperationAwarePolicyMatch`,
`OperationAwarePolicyRule`, `PolicyBundleScope`, `PolicyBundle`) — never a
raw dict passed in place of a typed object, and never a
`model_construct()`/validator-bypass escape hatch (this file's one
duplicate-`rule_id` scenario reaches its semantic-validation failure through
ordinary `PolicyBundle` construction, exactly as `bundle.py`'s own
docstring says it must: bundle-level `rule_id` uniqueness is deferred to
`validate_policy_bundle`, not enforced by `PolicyBundle.__init__` itself).

This is unit-level engine-integration coverage, not fixture-wired canonical
conformance. Each scenario's shape is hand-authored to *mirror* the logical
structure of the corresponding vendored v0.2.1 scenario (same kind of
request, same kind of rule/bundle, same outcome) — it does not load, parse,
or assert equality against any vendored YAML artifact. Full fixture-wired
conformance (byte-equal trace/response/audit-evidence comparison against
`tests/fixtures/basis-schemas/v0.2.1/compatibility/*/expected-*.yaml`)
remains Milestone 12's scope, not this file's.

What this file does not do
───────────────────────────
It does not mock, monkeypatch, or bypass any stage the engine orchestrates
(policy validation, applicability, candidate selection, selector/condition
evaluation, aggregation, rule-evidence assembly, or trace assembly) — every
scenario below calls `OperationAwareEvaluationEngine().evaluate(...)`
directly and lets every real stage run. It does not retest the exhaustive
per-stage permutations `test_evaluation_engine.py`, `test_policy_aggregation
.py`, and `test_trace_assembly.py` already own; it proves only that the five
canonical logical stories are reachable through the complete, real engine.
It asserts no expected `OperationAwareDecisionResponse`, `AuditEvidence`, or
gateway-event field — none of those exist in this repository yet.

No runtime fixture loading
────────────────────────────
This module imports no YAML library and neither of the two vendored-fixture
test helpers (`tests.helpers.basis_schemas_snapshot`,
`tests.helpers.operation_aware_contracts`) — see
`TestNoRuntimeFixtureLoading` below for a mechanical proof of this, in the
same AST-inspection style `test_evaluation_engine.py` already uses for its
own static guards.

Determinism
────────────
Every identifier below (`trace_id`, `request_id`, `correlation_id`,
`bundle_id`, `bundle_version`, `rule_id`) is a fixed literal string — no
`uuid`, no clock, no randomness. `test_allow_basic_canonical_shape` also
evaluates its one hand-constructed request/bundle pair twice under the same
`trace_id` and asserts the two resulting traces are equal, and confirms
neither the request nor the bundle was mutated by either call.
"""

from __future__ import annotations

import ast
import inspect
import sys

from basis_core.audit.operation_aware.evaluation_trace import (
    EvaluationStatus,
    TraceBundleApplicability,
    TraceFailureReason,
    TraceOutcome,
)
from basis_core.audit.operation_aware.trace_rule_evidence import RuleResult, TraceRuleEffect
from basis_core.decisions.operation_aware import OperationAwareDecisionRequest
from basis_core.evaluation.operation_aware.engine import OperationAwareEvaluationEngine
from basis_core.policy.operation_aware.bundle import PolicyBundle, PolicyBundleScope
from basis_core.policy.operation_aware.rule import (
    OperationAwarePolicyMatch,
    OperationAwarePolicyRule,
    RuleEffect,
)

# ══════════════════════════════════════════════════════════════════════════
# Fixed, deterministic construction constants
# ══════════════════════════════════════════════════════════════════════════

_BUNDLE_VERSION = "1.0.0"
_SCHEMA_VERSION = "0.2.1"
_POLICY_OWNER = "canonical-shapes-test"


# ══════════════════════════════════════════════════════════════════════════
# Small, test-only, deterministic builder functions
# ══════════════════════════════════════════════════════════════════════════
#
# Every builder constructs the real typed model directly (never a raw dict
# handed to the engine). Optional selector-shaped fields are included in the
# constructor call only when actually populated — `OperationAwarePolicyMatch`
# and `PolicyBundleScope` each reject an *explicit* null for any of their
# selector fields (see both modules' own docstrings, "Selector
# representation: `None` is an internal sentinel only"), so a builder that
# unconditionally passed `actions=None` would itself raise a
# `ValidationError`; omitting the keyword entirely is the correct way to
# request "no restriction" from these models.


def _request(
    *,
    request_id: str,
    subject_id: str,
    action: str,
    correlation_id: str | None = None,
    subject_roles: tuple[str, ...] = (),
    resource_type: str | None = None,
) -> OperationAwareDecisionRequest:
    return OperationAwareDecisionRequest(
        request_id=request_id,
        correlation_id=correlation_id,
        subject_id=subject_id,
        subject_roles=list(subject_roles),
        action=action,
        resource_type=resource_type,
    )


def _match(
    *,
    actions: tuple[str, ...] | None = None,
    subject_roles: tuple[str, ...] | None = None,
    resource_types: tuple[str, ...] | None = None,
) -> OperationAwarePolicyMatch:
    kwargs: dict[str, list[str]] = {}
    if actions is not None:
        kwargs["actions"] = list(actions)
    if subject_roles is not None:
        kwargs["subject_roles"] = list(subject_roles)
    if resource_types is not None:
        kwargs["resource_types"] = list(resource_types)
    return OperationAwarePolicyMatch(**kwargs)


def _rule(
    *,
    rule_id: str,
    effect: RuleEffect,
    match: OperationAwarePolicyMatch,
    reason_code: str | None = None,
    explanation: str | None = None,
) -> OperationAwarePolicyRule:
    return OperationAwarePolicyRule(
        rule_id=rule_id,
        effect=effect,
        match=match,
        reason_code=reason_code,
        explanation=explanation,
    )


def _scope(
    *,
    resource_types: tuple[str, ...] | None = None,
) -> PolicyBundleScope:
    kwargs: dict[str, list[str]] = {}
    if resource_types is not None:
        kwargs["resource_types"] = list(resource_types)
    return PolicyBundleScope(**kwargs)


def _bundle(
    *,
    bundle_id: str,
    rules: list[OperationAwarePolicyRule],
    scope: PolicyBundleScope | None = None,
) -> PolicyBundle:
    return PolicyBundle(
        bundle_id=bundle_id,
        bundle_version=_BUNDLE_VERSION,
        schema_version=_SCHEMA_VERSION,
        policy_owner=_POLICY_OWNER,
        scope=scope,
        rules=rules,
    )


# ══════════════════════════════════════════════════════════════════════════
# Scenario 1 — allow-basic
# ══════════════════════════════════════════════════════════════════════════


def test_allow_basic_canonical_shape() -> None:
    """Mirrors `compatibility/allow-basic`: one applicable, globally-scoped
    bundle; one matching ALLOW rule; no conditions. Also carries this file's
    required determinism/no-mutation proof — see the module docstring."""
    request = _request(
        request_id="req-canonical-allow-basic-0001",
        correlation_id="corr-canonical-allow-basic-0001",
        subject_id="svc-canonical-operator",
        subject_roles=("operator",),
        action="read:ahu",
        resource_type="ahu",
    )
    bundle = _bundle(
        bundle_id="bundle-canonical-allow-basic",
        rules=[
            _rule(
                rule_id="rule-allow-basic-01",
                effect=RuleEffect.ALLOW,
                match=_match(subject_roles=("operator",), actions=("read:ahu",)),
                reason_code="allow_rule_matched",
                explanation="Operators may read AHU telemetry.",
            )
        ],
    )

    request_before = request.model_dump(mode="json")
    bundle_before = bundle.model_dump(mode="json")

    engine = OperationAwareEvaluationEngine()
    trace = engine.evaluate(
        request=request, bundle=bundle, trace_id="trace-canonical-allow-basic-0001"
    )
    trace_again = engine.evaluate(
        request=request, bundle=bundle, trace_id="trace-canonical-allow-basic-0001"
    )

    # Determinism: identical inputs and trace_id produce an equal trace.
    assert trace == trace_again

    # Neither the request nor the bundle was mutated by either call.
    assert request.model_dump(mode="json") == request_before
    assert bundle.model_dump(mode="json") == bundle_before

    # Core logical shape.
    assert trace.evaluation_status is EvaluationStatus.COMPLETED
    assert trace.outcome is TraceOutcome.ALLOW
    assert trace.bundle_applicability is TraceBundleApplicability.APPLICABLE
    assert trace.failure_reason is None

    # Identifier provenance.
    assert trace.trace_id == "trace-canonical-allow-basic-0001"
    assert trace.request_id == request.request_id == "req-canonical-allow-basic-0001"
    assert trace.correlation_id == request.correlation_id == "corr-canonical-allow-basic-0001"
    assert trace.bundle_id == bundle.bundle_id == "bundle-canonical-allow-basic"
    assert trace.bundle_version == bundle.bundle_version == _BUNDLE_VERSION

    # Rule evidence.
    assert len(trace.rule_evidence) == 1
    evidence = trace.rule_evidence[0]
    assert evidence.rule_id == "rule-allow-basic-01"
    assert evidence.effect is TraceRuleEffect.ALLOW
    assert evidence.rule_result is RuleResult.MATCHED
    assert evidence.condition_results is None  # no conditions were authored or evaluated

    # Aggregation reason code and explanation.
    assert trace.reason_code == "allow_rule_matched"
    assert trace.explanation is None  # no approved aggregate-explanation source exists yet


# ══════════════════════════════════════════════════════════════════════════
# Scenario 2 — deny-precedence
# ══════════════════════════════════════════════════════════════════════════


def test_deny_precedence_canonical_shape() -> None:
    """Mirrors `compatibility/deny-precedence`: one applicable bundle
    containing a matching ALLOW rule (authored first) and a matching DENY
    rule (authored second); DENY wins unconditionally."""
    request = _request(
        request_id="req-canonical-deny-precedence-0001",
        correlation_id="corr-canonical-deny-precedence-0001",
        subject_id="svc-canonical-operator-2",
        subject_roles=("operator",),
        action="write:hvac:setpoint",
        resource_type="hvac",
    )
    allow_rule = _rule(
        rule_id="rule-allow-priority",
        effect=RuleEffect.ALLOW,
        match=_match(actions=("write:hvac:setpoint",)),
        reason_code="allow_rule_matched",
    )
    deny_rule = _rule(
        rule_id="rule-deny-interlock",
        effect=RuleEffect.DENY,
        match=_match(actions=("write:hvac:setpoint",)),
        reason_code="deny_rule_matched",
    )
    bundle = _bundle(
        bundle_id="bundle-canonical-deny-precedence",
        rules=[allow_rule, deny_rule],  # authored ALLOW-first, DENY-second
    )

    engine = OperationAwareEvaluationEngine()
    trace = engine.evaluate(
        request=request, bundle=bundle, trace_id="trace-canonical-deny-precedence-0001"
    )

    # Core logical shape.
    assert trace.evaluation_status is EvaluationStatus.COMPLETED
    assert trace.outcome is TraceOutcome.DENY
    assert trace.bundle_applicability is TraceBundleApplicability.APPLICABLE
    assert trace.failure_reason is None

    # Both evaluated rules appear — the matched ALLOW rule is not discarded
    # merely because DENY wins.
    assert {evidence.rule_id for evidence in trace.rule_evidence} == {
        "rule-allow-priority",
        "rule-deny-interlock",
    }
    assert len(trace.rule_evidence) == 2
    for evidence in trace.rule_evidence:
        assert evidence.rule_result is RuleResult.MATCHED

    # Deterministic evidence ordering: ascending rule_id (select_candidate_
    # rules's own established order), independent of authored order.
    assert [e.rule_id for e in trace.rule_evidence] == [
        "rule-allow-priority",
        "rule-deny-interlock",
    ]

    # Final reason code represents explicit deny-rule matching.
    assert trace.reason_code == "deny_rule_matched"
    assert trace.explanation is None

    # The final result is not dependent on first-match/authored-order
    # behavior: reversing authored order (DENY first, ALLOW second) must
    # still produce DENY, through the same real aggregation path.
    reversed_bundle = _bundle(
        bundle_id="bundle-canonical-deny-precedence-reversed",
        rules=[deny_rule, allow_rule],  # authored DENY-first, ALLOW-second
    )
    reversed_trace = engine.evaluate(
        request=request,
        bundle=reversed_bundle,
        trace_id="trace-canonical-deny-precedence-reversed-0001",
    )
    assert reversed_trace.outcome is TraceOutcome.DENY
    assert reversed_trace.reason_code == "deny_rule_matched"
    assert [e.rule_id for e in reversed_trace.rule_evidence] == [
        "rule-allow-priority",
        "rule-deny-interlock",
    ]


# ══════════════════════════════════════════════════════════════════════════
# Scenario 3 — default-deny
# ══════════════════════════════════════════════════════════════════════════


def test_default_deny_canonical_shape() -> None:
    """Mirrors `compatibility/default-deny`: one applicable, globally-scoped
    bundle with exactly one ALLOW rule whose selector does not match this
    request's subject role, and no DENY rule at all."""
    request = _request(
        request_id="req-canonical-default-deny-0001",
        subject_id="svc-canonical-vendor",
        subject_roles=("vendor",),
        action="read:ahu",
        resource_type="ahu",
    )
    bundle = _bundle(
        bundle_id="bundle-canonical-default-deny",
        rules=[
            _rule(
                rule_id="rule-allow-operator-only",
                effect=RuleEffect.ALLOW,
                match=_match(subject_roles=("operator",)),  # vendor subject won't match
                reason_code="allow_rule_matched",
            )
        ],
    )

    engine = OperationAwareEvaluationEngine()
    trace = engine.evaluate(
        request=request, bundle=bundle, trace_id="trace-canonical-default-deny-0001"
    )

    # Core logical shape.
    assert trace.evaluation_status is EvaluationStatus.COMPLETED
    assert trace.outcome is TraceOutcome.DENY
    assert trace.bundle_applicability is TraceBundleApplicability.APPLICABLE
    assert trace.failure_reason is None

    # The one candidate rule is honestly recorded as not matched — never
    # falsely reported matched, and no condition evidence is fabricated for
    # it (it has no conditions and its selector already mismatched).
    assert len(trace.rule_evidence) == 1
    evidence = trace.rule_evidence[0]
    assert evidence.rule_id == "rule-allow-operator-only"
    assert evidence.rule_result is RuleResult.NOT_MATCHED
    assert evidence.condition_results is None

    # Default-deny's reason code is distinguishable from explicit deny
    # precedence's reason code (proven against Scenario 2's own result).
    assert trace.reason_code == "no_allow_rule_matched"
    assert trace.reason_code != "deny_rule_matched"
    assert trace.explanation is None


# ══════════════════════════════════════════════════════════════════════════
# Scenario 4 — not-applicable
# ══════════════════════════════════════════════════════════════════════════


def test_not_applicable_canonical_shape() -> None:
    """Mirrors `compatibility/not-applicable`: a bundle whose declared scope
    (`resource_types: [hvac]`) does not cover this request's `resource_type`
    (`chiller`) at all — a straightforward single-dimension scope
    mismatch."""
    request = _request(
        request_id="req-canonical-not-applicable-0001",
        subject_id="svc-canonical-operator-3",
        subject_roles=("operator",),
        action="read:chiller",
        resource_type="chiller",
    )
    bundle = _bundle(
        bundle_id="bundle-canonical-not-applicable",
        scope=_scope(resource_types=("hvac",)),
        rules=[
            _rule(
                rule_id="rule-allow-hvac-only",
                effect=RuleEffect.ALLOW,
                match=_match(resource_types=("hvac",)),
                reason_code="allow_rule_matched",
            )
        ],
    )

    engine = OperationAwareEvaluationEngine()
    trace = engine.evaluate(
        request=request, bundle=bundle, trace_id="trace-canonical-not-applicable-0001"
    )

    # Core logical shape — NOT_APPLICABLE is never converted to DENY.
    assert trace.evaluation_status is EvaluationStatus.COMPLETED
    assert trace.outcome is TraceOutcome.NOT_APPLICABLE
    assert trace.outcome is not TraceOutcome.DENY
    assert trace.bundle_applicability is TraceBundleApplicability.NOT_APPLICABLE
    assert trace.failure_reason is None

    # No rule was ever a candidate — no evidence is fabricated.
    assert trace.rule_evidence == []

    # Identifier provenance: the engine's non-applicable path still reports
    # the bundle's own identity fields (see `engine.py::_assemble_trace`,
    # which is shared by both the applicable and non-applicable paths).
    assert trace.trace_id == "trace-canonical-not-applicable-0001"
    assert trace.request_id == request.request_id
    assert trace.correlation_id == request.correlation_id is None
    assert trace.bundle_id == bundle.bundle_id == "bundle-canonical-not-applicable"
    assert trace.bundle_version == bundle.bundle_version == _BUNDLE_VERSION

    # Final reason code is the existing no-applicable-bundle reason.
    assert trace.reason_code == "no_applicable_bundle"
    assert trace.explanation is None


# ══════════════════════════════════════════════════════════════════════════
# Scenario 5 — invalid-policy-bundle
# ══════════════════════════════════════════════════════════════════════════


def test_invalid_policy_bundle_canonical_shape() -> None:
    """Mirrors `compatibility/invalid-policy-bundle`: two otherwise valid
    rules sharing the same `rule_id`, the one and only semantic defect.
    `PolicyBundle`'s own constructor does not reject duplicate `rule_id`
    values (that check is deferred to `validate_policy_bundle`, PR 15 — see
    `bundle.py`'s docstring, "Deferred to PR 15") — so this bundle is built
    through ordinary, unmodified `PolicyBundle` construction, exactly like
    any other bundle in this file; no `model_construct()` escape hatch is
    needed or used."""
    request = _request(
        request_id="req-canonical-invalid-policy-0001",
        correlation_id="corr-canonical-invalid-policy-0001",
        subject_id="svc-canonical-operator-4",
        action="read:ahu",
    )
    duplicate_allow = _rule(
        rule_id="dup-rule-canonical",
        effect=RuleEffect.ALLOW,
        match=_match(actions=("read:ahu",)),
    )
    duplicate_deny = _rule(
        rule_id="dup-rule-canonical",  # same rule_id as duplicate_allow
        effect=RuleEffect.DENY,
        match=_match(actions=("write:ahu",)),
    )
    bundle = _bundle(
        bundle_id="bundle-canonical-invalid-policy",
        rules=[duplicate_allow, duplicate_deny],
    )
    # Duplicate rule_id never reaches successful rule evaluation: ordinary
    # construction above already proves the bundle itself builds fine
    # (structural shape is not the defect) — the failure below is entirely
    # `validate_policy_bundle`'s semantic stage, invoked as the engine's own
    # Stage 1.
    assert bundle.rules[0].rule_id == bundle.rules[1].rule_id == "dup-rule-canonical"

    engine = OperationAwareEvaluationEngine()
    trace = engine.evaluate(
        request=request, bundle=bundle, trace_id="trace-canonical-invalid-policy-0001"
    )

    # Core logical shape — no authorization outcome is produced, and
    # failure is not converted to DENY.
    assert trace.evaluation_status is EvaluationStatus.FAILED
    assert trace.outcome is None
    assert trace.outcome is not TraceOutcome.DENY
    assert trace.bundle_applicability is None
    assert trace.failure_reason is TraceFailureReason.POLICY_VALIDATION_FAILURE

    # No rule evidence is fabricated — validation failure occurs before any
    # rule is ever evaluated.
    assert trace.rule_evidence == []

    # Identifier provenance.
    assert trace.trace_id == "trace-canonical-invalid-policy-0001"
    assert trace.request_id == request.request_id
    assert trace.correlation_id == request.correlation_id == "corr-canonical-invalid-policy-0001"
    assert trace.bundle_id == bundle.bundle_id == "bundle-canonical-invalid-policy"
    assert trace.bundle_version == bundle.bundle_version == _BUNDLE_VERSION

    # The final reason code is absent; no explanation is invented.
    assert trace.reason_code is None
    assert trace.explanation is None


# ══════════════════════════════════════════════════════════════════════════
# Static guard — no runtime fixture loading
# ══════════════════════════════════════════════════════════════════════════


def test_module_does_not_import_yaml_or_snapshot_helpers() -> None:
    """Mechanical proof that this module never loads the vendored v0.2.1
    compatibility fixtures at runtime — see the module docstring, "No
    runtime fixture loading". Style mirrors the AST-based static guards
    `test_evaluation_engine.py` already uses (e.g.
    `test_no_clock_uuid_random_or_environment_dependency`)."""
    source = inspect.getsource(sys.modules[__name__])
    tree = ast.parse(source)
    imported_modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported_modules.append(node.module)
        elif isinstance(node, ast.Import):
            imported_modules.extend(alias.name for alias in node.names)

    forbidden_prefixes = (
        "yaml",
        "tests.helpers.basis_schemas_snapshot",
        "tests.helpers.operation_aware_contracts",
    )
    violations = [
        module
        for module in imported_modules
        if any(module == prefix or module.startswith(prefix + ".") for prefix in forbidden_prefixes)
    ]
    assert violations == [], (
        f"test_engine_canonical_shapes.py must not import a fixture-loading "
        f"module at runtime; found: {violations}"
    )
