"""
tests/operation_aware/test_canonical_vectors.py — canonical end-to-end
conformance tests (Milestone 12, PR 37 of
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`: "Wire the
five canonical scenarios end-to-end").

Objective
─────────
Wire all five vendored operation-aware canonical compatibility-vector
scenarios (`tests/fixtures/basis-schemas/v0.2.1/compatibility/*/`) through
the real operation-aware kernel enforcement path — typed request
+ typed policy bundle, through `OperationAwareEnforcementPoint.evaluate()`,
through `OperationAwareEvaluationEngine`, through policy-owned evaluation,
through `EvaluationTrace`, through response assembly, through
`AuditEvidence` assembly — and assert complete semantic equality between
the actual `OperationAwareDecisionResponse` / `EvaluationTrace` /
`AuditEvidence` this repository's kernel produces and the vendored expected
artifacts `basis-schemas` publishes. This is the terminal conformance proof
(Section 10 of the roadmap plan) that every previously implemented model,
policy semantic, evaluation orchestration, artifact assembler, and
enforcement composition collectively reproduces the outputs the upstream
contract publisher expects.

This is a test-only implementation milestone. No production code, vendored
fixture, or existing test helper is modified by this module.

Scope — what this module does and does not do
────────────────────────────────────────────────────────────────────────────
This module loads real vendored fixtures (never hand-typed expected
values), constructs real typed production models (never
`model_construct()`, never a raw dict handed to the engine or enforcement
point), and invokes the real `OperationAwareEnforcementPoint` twice per
scenario — once reference-only, once with the trace embedded — comparing
each of the three published artifacts against its own vendored expected
fixture, validated into the same real production model. It does not
substitute a test double of any kind for the engine, the bundle, or any
assembler — every stage below runs its real, complete implementation. It
does not independently recompute an expected outcome, reason code, matched
rule-ID list, failure reason, bundle identity, or trace-evidence
entry — every expected value below is loaded from a vendored fixture, never
hand-authored. It does not load, construct, or assert against the
gateway-only expected event fixture or its corresponding gateway-owned
production type — that artifact sits outside this repository's kernel
boundary, and documenting the exclusion explicitly is PR 38's dedicated
scope, not this PR's.

Active snapshot
────────────────
This module resolves fixtures exclusively through the existing,
already-reviewed discovery helpers (`tests.helpers.basis_schemas_snapshot`,
`tests.helpers.operation_aware_contracts`) — never a second YAML loader,
never a hand-constructed path, never a machine-specific path, never a
network fetch, never a live `basis-schemas` checkout. `SNAPSHOT_RELEASE`
(`tests/helpers/basis_schemas_snapshot.py`) currently resolves to `v0.2.2`
— the corrected snapshot whose `invalid-policy-bundle` scenario publishes
`failure_reason: policy_validation_failure` (not the historical `v0.2.0`
snapshot's superseded `invalid_policy_bundle` classification), and which
further corrects the `v0.2.1` snapshot's `invalid-policy-bundle` artifacts
to retain `bundle_id`/`bundle_version` provenance for the specific typed
bundle that was evaluated and rejected, and to publish a null top-level
`explanation` (an authored explanation is never fabricated for a failed
evaluation). A test below asserts this pinned value directly, so a future
accidental snapshot downgrade fails loudly here rather than silently
comparing against a retired fixture set.

Caller-supplied facts
────────────────────────
`OperationAwareEnforcementPoint.evaluate()` requires `trace_id`,
`evidence_id`, and `recorded_at` — facts the kernel deliberately does not
generate (ADR-0006 Decision 4). This module derives all three from the
canonical expected fixtures themselves (`expected_trace.trace_id`,
`expected_audit.evidence_id`, `expected_audit.recorded_at`) and passes them
verbatim; it never generates a fresh identifier and never reads the system
clock or any other nondeterministic source.

Reference-only and embedded-trace executions
────────────────────────────────────────────────
The vendored `expected-operation-aware-decision-response.yaml` fixtures are
all reference-only (`trace_id` present, `evaluation_trace` absent). To
compare both the canonical reference-only response *and* a real,
enforcement-produced complete `EvaluationTrace` against the canonical
expected trace, this module invokes `OperationAwareEnforcementPoint.evaluate()`
twice per scenario, under identical typed inputs and identical
caller-supplied facts — once with `embed_evaluation_trace=False` (compared
against the expected response and expected `AuditEvidence`), once with
`embed_evaluation_trace=True` (whose `response.evaluation_trace` is
compared against the expected `EvaluationTrace`). Both executions are
proven to agree on every shared evaluation fact, so this is not two
independent evaluations of the scenario — it is the same real evaluation
observed through both response shapes the enforcement point supports.

No second evaluator
────────────────────
This module contains scenario loading, typed model construction,
fixture-consistency preconditions, model equality checks, serialized-dump
comparisons, and small test-owned per-scenario assertion helpers. It
contains no logic that independently implements
bundle applicability, selector matching, condition evaluation, operator
semantics, rule matching, deny precedence, allow determination, default
deny, `NOT_APPLICABLE`, failure classification, trace assembly,
matched-rule projection, response assembly, or audit-evidence assembly.
Every expected value compared below is loaded from a vendored fixture and
validated into the real production model that fixture describes — never
computed by this module from the request and bundle.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from basis_core.audit import AuditEvidence, EvaluationTrace
from basis_core.decisions import (
    OperationAwareDecisionOutcome,
    OperationAwareDecisionRequest,
    OperationAwareEvaluationStatus,
    OperationAwareFailureReason,
)
from basis_core.enforcement import (
    EnforcementDisposition,
    OperationAwareEnforcementPoint,
    OperationAwareEnforcementResult,
)
from basis_core.evaluation.operation_aware.engine import OperationAwareEvaluationEngine
from basis_core.evaluation.operation_aware.response import OperationAwareDecisionResponse
from basis_core.policy import PolicyBundle
from tests.helpers.basis_schemas_snapshot import (
    COMPATIBILITY_SCENARIOS,
    KERNEL_SCENARIO_ARTIFACTS,
    SNAPSHOT_RELEASE,
    list_compatibility_scenarios,
)
from tests.helpers.operation_aware_contracts import load_scenario_artifact

# ══════════════════════════════════════════════════════════════════════════
# Canonical scenario inventory
# ══════════════════════════════════════════════════════════════════════════

CANONICAL_SCENARIOS: tuple[str, ...] = (
    "allow-basic",
    "deny-precedence",
    "default-deny",
    "not-applicable",
    "invalid-policy-bundle",
)

#: The five logical, kernel-owned artifacts every canonical scenario
#: publishes. Deliberately excludes `expected_gateway_audit_event` — see
#: this module's docstring, "Scope," and `GATEWAY_ONLY_SCENARIO_ARTIFACTS`
#: in `tests.helpers.basis_schemas_snapshot`.
_EXPECTED_KERNEL_ARTIFACTS: frozenset[str] = frozenset(
    {
        "request",
        "policy_bundle",
        "expected_evaluation_trace",
        "expected_response",
        "expected_audit_evidence",
    }
)


class TestActiveSnapshotAndScenarioInventory:
    """Guards against silently running this PR's conformance proof against
    the wrong snapshot, an incomplete scenario list, or a misspelled
    scenario name — see this module's docstring, "Active snapshot"."""

    def test_active_snapshot_release_is_the_corrected_v0_2_2(self) -> None:
        assert SNAPSHOT_RELEASE == "v0.2.2", (
            "This PR's conformance proof requires the corrected v0.2.2 snapshot "
            "(failure_reason: policy_validation_failure and preserved bundle "
            "identity for invalid-policy-bundle), "
            f"not {SNAPSHOT_RELEASE!r}."
        )

    def test_canonical_scenarios_constant_has_exactly_five_entries(self) -> None:
        assert len(CANONICAL_SCENARIOS) == 5
        assert len(set(CANONICAL_SCENARIOS)) == 5  # no duplicate/misspelled entry

    def test_test_owned_inventory_matches_disk_discovered_snapshot_inventory(self) -> None:
        """Verified against the active snapshot's own disk-discovered
        inventory (`list_compatibility_scenarios()`), not merely trusted
        against the `COMPATIBILITY_SCENARIOS` constant alone."""
        on_disk = list_compatibility_scenarios()
        assert set(CANONICAL_SCENARIOS) == set(on_disk), (
            f"CANONICAL_SCENARIOS {sorted(CANONICAL_SCENARIOS)} does not match the "
            f"vendored {SNAPSHOT_RELEASE} snapshot's on-disk scenario inventory "
            f"{sorted(on_disk)}."
        )
        assert len(CANONICAL_SCENARIOS) == len(on_disk)

    def test_test_owned_inventory_matches_helper_constant_inventory(self) -> None:
        assert set(CANONICAL_SCENARIOS) == set(COMPATIBILITY_SCENARIOS)


class TestKernelArtifactInventory:
    """The kernel-owned result-artifact inventory this PR compares against
    — proven distinct from the gateway-only artifact this PR must never
    assert against."""

    def test_kernel_scenario_artifacts_matches_expected_five(self) -> None:
        assert set(KERNEL_SCENARIO_ARTIFACTS) == _EXPECTED_KERNEL_ARTIFACTS

    def test_gateway_audit_event_is_not_a_kernel_artifact(self) -> None:
        assert "expected_gateway_audit_event" not in KERNEL_SCENARIO_ARTIFACTS


# ══════════════════════════════════════════════════════════════════════════
# Fixture loading — real vendored fixtures, real typed production models
# ══════════════════════════════════════════════════════════════════════════


def _load_typed_request(scenario: str) -> OperationAwareDecisionRequest:
    raw = load_scenario_artifact(scenario, "request")
    return OperationAwareDecisionRequest.model_validate(raw)


def _load_typed_bundle(scenario: str) -> PolicyBundle:
    """Loads `policy_bundle` (the logical artifact name) — the existing
    `get_scenario_artifact`/`_artifact_filenames_for` helper already
    resolves this to `invalid-policy-bundle.yaml` for the
    `invalid-policy-bundle` scenario and `policy-bundle.yaml` for the other
    four; this module does not re-implement that filename switch.

    Constructed through ordinary `PolicyBundle.model_validate` — never
    `model_construct()`. For `invalid-policy-bundle`, this is expected to
    succeed: the fixture is structurally well-formed (its one defect,
    duplicate `rule_id`, is a semantic-validation concern the engine's own
    Stage 1 rejects, not a structural-construction concern — see
    `engine.py`'s docstring)."""
    raw = load_scenario_artifact(scenario, "policy_bundle")
    return PolicyBundle.model_validate(raw)


def _load_expected_trace(scenario: str) -> EvaluationTrace:
    raw = load_scenario_artifact(scenario, "expected_evaluation_trace")
    return EvaluationTrace.model_validate(raw)


def _load_expected_response(scenario: str) -> OperationAwareDecisionResponse:
    raw = load_scenario_artifact(scenario, "expected_response")
    return OperationAwareDecisionResponse.model_validate(raw)


def _load_expected_audit_evidence(scenario: str) -> AuditEvidence:
    raw = load_scenario_artifact(scenario, "expected_audit_evidence")
    return AuditEvidence.model_validate(raw)


# ══════════════════════════════════════════════════════════════════════════
# Fixture-consistency preconditions — not a second evaluator; these check
# only that the vendored expected fixtures agree with each other and with
# the request/bundle, before any enforcement invocation.
# ══════════════════════════════════════════════════════════════════════════


def _assert_fixture_consistency(
    *,
    scenario: str,
    request: OperationAwareDecisionRequest,
    bundle: PolicyBundle,
    expected_response: OperationAwareDecisionResponse,
    expected_trace: EvaluationTrace,
    expected_audit: AuditEvidence,
) -> None:
    # ── request/correlation identity agrees across every fixture ────────
    assert expected_response.request_id == expected_trace.request_id, (
        f"{scenario}: expected response request_id {expected_response.request_id!r} "
        f"disagrees with expected trace request_id {expected_trace.request_id!r}."
    )
    assert expected_audit.request_id == expected_trace.request_id, (
        f"{scenario}: expected audit request_id {expected_audit.request_id!r} "
        f"disagrees with expected trace request_id {expected_trace.request_id!r}."
    )
    assert request.request_id == expected_trace.request_id, (
        f"{scenario}: request fixture request_id {request.request_id!r} disagrees "
        f"with expected trace request_id {expected_trace.request_id!r}."
    )
    assert request.correlation_id == expected_trace.correlation_id, (
        f"{scenario}: request fixture correlation_id {request.correlation_id!r} "
        f"disagrees with expected trace correlation_id {expected_trace.correlation_id!r}."
    )
    assert expected_response.correlation_id == expected_trace.correlation_id, (
        f"{scenario}: expected response correlation_id "
        f"{expected_response.correlation_id!r} disagrees with expected trace "
        f"correlation_id {expected_trace.correlation_id!r}."
    )
    assert expected_audit.correlation_id == expected_trace.correlation_id, (
        f"{scenario}: expected audit correlation_id {expected_audit.correlation_id!r} "
        f"disagrees with expected trace correlation_id {expected_trace.correlation_id!r}."
    )

    # ── trace_id references, where present ───────────────────────────────
    if expected_response.trace_id is not None:
        assert expected_response.trace_id == expected_trace.trace_id, (
            f"{scenario}: expected response trace_id {expected_response.trace_id!r} "
            f"disagrees with expected trace trace_id {expected_trace.trace_id!r}."
        )
    if expected_audit.trace_id is not None:
        assert expected_audit.trace_id == expected_trace.trace_id, (
            f"{scenario}: expected audit trace_id {expected_audit.trace_id!r} disagrees "
            f"with expected trace trace_id {expected_trace.trace_id!r}."
        )

    # ── bundle identity/version, where the artifacts carry them ──────────
    if expected_trace.bundle_id is not None:
        assert expected_trace.bundle_id == bundle.bundle_id, (
            f"{scenario}: expected trace bundle_id {expected_trace.bundle_id!r} "
            f"disagrees with the input bundle's bundle_id {bundle.bundle_id!r}."
        )
    if expected_trace.bundle_version is not None:
        assert expected_trace.bundle_version == bundle.bundle_version, (
            f"{scenario}: expected trace bundle_version {expected_trace.bundle_version!r} "
            f"disagrees with the input bundle's bundle_version {bundle.bundle_version!r}."
        )
    if expected_response.bundle_id is not None:
        assert expected_response.bundle_id == bundle.bundle_id
    if expected_audit.bundle_id is not None:
        assert expected_audit.bundle_id == bundle.bundle_id

    # ── evaluation-state fields agree across response/trace/audit ────────
    # Compared by closed-vocabulary *value* — EvaluationTrace uses
    # audit-owned local vocabulary (EvaluationStatus/TraceOutcome/
    # TraceFailureReason); OperationAwareDecisionResponse/AuditEvidence use
    # decisions-owned vocabulary (OperationAwareEvaluationStatus/
    # OperationAwareDecisionOutcome/OperationAwareFailureReason). Both
    # families are published as value- and member-name-parity-tested
    # elsewhere (test_response_assembly.py, test_artifact_agreement.py);
    # this is a literal string-value equality check on already-loaded
    # fixture fields, not a semantic mapping computation.
    assert expected_response.evaluation_status.value == expected_trace.evaluation_status.value
    assert expected_audit.evaluation_status.value == expected_trace.evaluation_status.value

    trace_outcome_value = (
        expected_trace.outcome.value if expected_trace.outcome is not None else None
    )
    response_outcome_value = (
        expected_response.outcome.value if expected_response.outcome is not None else None
    )
    audit_outcome_value = (
        expected_audit.outcome.value if expected_audit.outcome is not None else None
    )
    assert response_outcome_value == trace_outcome_value, (
        f"{scenario}: expected response outcome {response_outcome_value!r} disagrees "
        f"with expected trace outcome {trace_outcome_value!r}."
    )
    assert audit_outcome_value == trace_outcome_value, (
        f"{scenario}: expected audit outcome {audit_outcome_value!r} disagrees with "
        f"expected trace outcome {trace_outcome_value!r}."
    )

    trace_failure_value = (
        expected_trace.failure_reason.value if expected_trace.failure_reason is not None else None
    )
    response_failure_value = (
        expected_response.failure_reason.value
        if expected_response.failure_reason is not None
        else None
    )
    audit_failure_value = (
        expected_audit.failure_reason.value if expected_audit.failure_reason is not None else None
    )
    assert response_failure_value == trace_failure_value, (
        f"{scenario}: expected response failure_reason {response_failure_value!r} "
        f"disagrees with expected trace failure_reason {trace_failure_value!r}."
    )
    assert audit_failure_value == trace_failure_value, (
        f"{scenario}: expected audit failure_reason {audit_failure_value!r} disagrees "
        f"with expected trace failure_reason {trace_failure_value!r}."
    )


class TestFixtureInternalAgreement:
    """Fixture-consistency preconditions only — no enforcement invocation.
    A failure here identifies a vendored-fixture disagreement, distinct
    from a kernel-conformance failure in `TestCanonicalConformance` below."""

    @pytest.mark.parametrize("scenario", CANONICAL_SCENARIOS, ids=CANONICAL_SCENARIOS)
    def test_expected_fixtures_agree_with_each_other_and_the_inputs(self, scenario: str) -> None:
        request = _load_typed_request(scenario)
        bundle = _load_typed_bundle(scenario)
        expected_response = _load_expected_response(scenario)
        expected_trace = _load_expected_trace(scenario)
        expected_audit = _load_expected_audit_evidence(scenario)
        _assert_fixture_consistency(
            scenario=scenario,
            request=request,
            bundle=bundle,
            expected_response=expected_response,
            expected_trace=expected_trace,
            expected_audit=expected_audit,
        )


# ══════════════════════════════════════════════════════════════════════════
# Enforcement disposition — derived from the already-validated expected
# response state (ADR-0006 Decision 7's mapping, stated here as an
# assertion, not re-implemented as production logic).
# ══════════════════════════════════════════════════════════════════════════


def _expected_disposition(
    expected_response: OperationAwareDecisionResponse,
) -> EnforcementDisposition:
    if (
        expected_response.evaluation_status is OperationAwareEvaluationStatus.COMPLETED
        and expected_response.outcome is OperationAwareDecisionOutcome.ALLOW
    ):
        return EnforcementDisposition.ALLOW
    return EnforcementDisposition.DENY


# ══════════════════════════════════════════════════════════════════════════
# Scenario-specific semantic protections
# ══════════════════════════════════════════════════════════════════════════


def _assert_allow_basic(
    reference_result: OperationAwareEnforcementResult,
    embedded_result: OperationAwareEnforcementResult,
) -> None:
    for result in (reference_result, embedded_result):
        assert result.response.evaluation_status is OperationAwareEvaluationStatus.COMPLETED
        assert result.response.outcome is OperationAwareDecisionOutcome.ALLOW
        assert result.disposition is EnforcementDisposition.ALLOW
        assert result.audit_evidence is not None


def _assert_deny_precedence(
    reference_result: OperationAwareEnforcementResult,
    embedded_result: OperationAwareEnforcementResult,
) -> None:
    # Rule-ordering-independence for deny precedence is already covered by
    # lower-level deterministic tests (test_policy_aggregation.py,
    # test_engine_canonical_shapes.py's reversed-order assertion) — not
    # re-run here per this PR's own scope restraint.
    for result in (reference_result, embedded_result):
        assert result.response.evaluation_status is OperationAwareEvaluationStatus.COMPLETED
        assert result.response.outcome is OperationAwareDecisionOutcome.DENY
        assert result.disposition is EnforcementDisposition.DENY
        assert result.audit_evidence is not None


def _assert_default_deny(
    reference_result: OperationAwareEnforcementResult,
    embedded_result: OperationAwareEnforcementResult,
) -> None:
    for result in (reference_result, embedded_result):
        assert result.response.evaluation_status is OperationAwareEvaluationStatus.COMPLETED
        assert result.response.outcome is OperationAwareDecisionOutcome.DENY
        assert result.disposition is EnforcementDisposition.DENY
        assert result.audit_evidence is not None
        assert result.audit_evidence.matched_rule_ids == []


def _assert_not_applicable(
    reference_result: OperationAwareEnforcementResult,
    embedded_result: OperationAwareEnforcementResult,
) -> None:
    for result in (reference_result, embedded_result):
        assert result.response.evaluation_status is OperationAwareEvaluationStatus.COMPLETED
        assert result.response.outcome is OperationAwareDecisionOutcome.NOT_APPLICABLE
        # Fail-closed enforcement disposition never rewrites the
        # authoritative response — outcome stays not_applicable, never deny.
        assert result.response.outcome is not OperationAwareDecisionOutcome.DENY
        assert result.disposition is EnforcementDisposition.DENY
        assert result.audit_evidence is not None


def _assert_invalid_policy_bundle(
    reference_result: OperationAwareEnforcementResult,
    embedded_result: OperationAwareEnforcementResult,
) -> None:
    for result in (reference_result, embedded_result):
        assert result.response.evaluation_status is OperationAwareEvaluationStatus.FAILED
        assert result.response.outcome is None
        assert (
            result.response.failure_reason is OperationAwareFailureReason.POLICY_VALIDATION_FAILURE
        )
        assert (
            result.response.failure_reason is not OperationAwareFailureReason.INVALID_POLICY_BUNDLE
        )
        assert result.disposition is EnforcementDisposition.DENY
        # A failed evaluation is not a substantive authorization denial —
        # AuditEvidence is still produced (evaluation_status: failed,
        # outcome: null), never fabricated as a deny decision.
        assert result.audit_evidence is not None
        assert result.audit_evidence.outcome is None


_SCENARIO_SPECIFIC_ASSERTIONS: dict[
    str,
    Callable[[OperationAwareEnforcementResult, OperationAwareEnforcementResult], None],
] = {
    "allow-basic": _assert_allow_basic,
    "deny-precedence": _assert_deny_precedence,
    "default-deny": _assert_default_deny,
    "not-applicable": _assert_not_applicable,
    "invalid-policy-bundle": _assert_invalid_policy_bundle,
}


# ══════════════════════════════════════════════════════════════════════════
# The canonical end-to-end conformance test
# ══════════════════════════════════════════════════════════════════════════


class TestCanonicalConformance:
    @pytest.mark.parametrize("scenario", CANONICAL_SCENARIOS, ids=CANONICAL_SCENARIOS)
    def test_end_to_end_canonical_conformance(self, scenario: str) -> None:
        # ── Load real vendored fixtures; construct real typed models ─────
        request = _load_typed_request(scenario)
        bundle = _load_typed_bundle(scenario)
        expected_trace = _load_expected_trace(scenario)
        expected_response = _load_expected_response(scenario)
        expected_audit = _load_expected_audit_evidence(scenario)

        _assert_fixture_consistency(
            scenario=scenario,
            request=request,
            bundle=bundle,
            expected_response=expected_response,
            expected_trace=expected_trace,
            expected_audit=expected_audit,
        )

        # Captured before any enforcement invocation — compared again at
        # the end of this test to prove input/expected-fixture immutability.
        request_before = request.model_dump(mode="json")
        bundle_before = bundle.model_dump(mode="json")
        expected_trace_before = expected_trace.model_dump(mode="json")
        expected_response_before = expected_response.model_dump(mode="json")
        expected_audit_before = expected_audit.model_dump(mode="json")

        # ── Real end-to-end execution ─────────────────────────────────────
        engine = OperationAwareEvaluationEngine()
        enforcement_point = OperationAwareEnforcementPoint(engine=engine, bundle=bundle)

        # Caller-supplied facts, derived verbatim from the canonical
        # expected fixtures — never generated by this test or by the kernel.
        trace_id = expected_trace.trace_id
        evidence_id = expected_audit.evidence_id
        recorded_at = expected_audit.recorded_at

        reference_result = enforcement_point.evaluate(
            request=request,
            trace_id=trace_id,
            evidence_id=evidence_id,
            recorded_at=recorded_at,
            embed_evaluation_trace=False,
        )
        embedded_result = enforcement_point.evaluate(
            request=request,
            trace_id=trace_id,
            evidence_id=evidence_id,
            recorded_at=recorded_at,
            embed_evaluation_trace=True,
        )
        # Repeat-run determinism: identical inputs and facts, run again.
        repeat_reference_result = enforcement_point.evaluate(
            request=request,
            trace_id=trace_id,
            evidence_id=evidence_id,
            recorded_at=recorded_at,
            embed_evaluation_trace=False,
        )

        # ── Reference-only / embedded shape invariants ────────────────────
        assert reference_result.response.evaluation_trace is None
        assert reference_result.response.trace_id == expected_trace.trace_id
        assert reference_result.audit_evidence is not None

        assert embedded_result.response.evaluation_trace is not None

        # ── Response equality (reference-only run vs. canonical expected) ─
        assert reference_result.response == expected_response, (
            f"{scenario}: actual reference-only OperationAwareDecisionResponse does not "
            f"equal the vendored expected response.\nactual="
            f"{reference_result.response!r}\nexpected={expected_response!r}"
        )
        assert reference_result.response.model_dump(
            mode="json", exclude_none=True
        ) == expected_response.model_dump(mode="json", exclude_none=True)

        # ── Trace equality (embedded run's complete trace vs. canonical) ──
        actual_trace = embedded_result.response.evaluation_trace
        assert actual_trace == expected_trace, (
            f"{scenario}: actual embedded EvaluationTrace does not equal the vendored "
            f"expected trace.\nactual={actual_trace!r}\nexpected={expected_trace!r}"
        )
        assert actual_trace is not None
        assert actual_trace.model_dump(mode="json", exclude_none=True) == expected_trace.model_dump(
            mode="json", exclude_none=True
        )

        # ── AuditEvidence equality (both runs assemble equal evidence) ────
        assert reference_result.audit_evidence == expected_audit, (
            f"{scenario}: actual reference-only AuditEvidence does not equal the "
            f"vendored expected audit evidence.\nactual={reference_result.audit_evidence!r}"
            f"\nexpected={expected_audit!r}"
        )
        assert embedded_result.audit_evidence == expected_audit
        assert reference_result.audit_evidence == embedded_result.audit_evidence
        assert reference_result.audit_evidence is not None
        assert reference_result.audit_evidence.model_dump(
            mode="json", exclude_none=True
        ) == expected_audit.model_dump(mode="json", exclude_none=True)

        # ── Both real executions agree on every shared evaluation fact ────
        assert reference_result.response.request_id == embedded_result.response.request_id
        assert reference_result.response.correlation_id == embedded_result.response.correlation_id
        assert (
            reference_result.response.evaluation_status
            == embedded_result.response.evaluation_status
        )
        assert reference_result.response.outcome == embedded_result.response.outcome
        assert reference_result.response.failure_reason == embedded_result.response.failure_reason
        assert reference_result.response.bundle_id == embedded_result.response.bundle_id
        assert reference_result.response.bundle_version == embedded_result.response.bundle_version
        assert reference_result.response.trace_id == embedded_result.response.trace_id
        assert reference_result.response.reason_code == embedded_result.response.reason_code
        assert reference_result.response.explanation == embedded_result.response.explanation
        assert reference_result.audit_evidence == embedded_result.audit_evidence
        assert reference_result.disposition == embedded_result.disposition

        # ── Enforcement disposition (integrated invariant, not a canonical
        #    artifact — derived from the already-validated expected
        #    response state) ─────────────────────────────────────────────
        expected_disposition = _expected_disposition(expected_response)
        assert reference_result.disposition is expected_disposition
        assert embedded_result.disposition is expected_disposition

        # ── Scenario-specific semantic protections ────────────────────────
        _SCENARIO_SPECIFIC_ASSERTIONS[scenario](reference_result, embedded_result)

        # ── Repeat-run determinism ─────────────────────────────────────────
        assert repeat_reference_result == reference_result
        assert repeat_reference_result.response == reference_result.response
        assert repeat_reference_result.audit_evidence == reference_result.audit_evidence
        assert repeat_reference_result.disposition == reference_result.disposition

        # ── Input / expected-fixture immutability ──────────────────────────
        assert request.model_dump(mode="json") == request_before
        assert bundle.model_dump(mode="json") == bundle_before
        assert expected_trace.model_dump(mode="json") == expected_trace_before
        assert expected_response.model_dump(mode="json") == expected_response_before
        assert expected_audit.model_dump(mode="json") == expected_audit_before


# Scope restraint (no gateway-owned reference, no test-double evaluator, no
# nondeterministic generation, no direct engine invocation bypassing the
# enforcement point) is verified externally via the repository's own
# text-search scope-verification step against this file, rather than by an
# in-module self-scanning test — a self-scanning assertion would need to
# embed the very substrings it searches for, which would itself always
# match its own search pattern.
