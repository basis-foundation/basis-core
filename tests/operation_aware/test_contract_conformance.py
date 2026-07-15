"""
tests/operation_aware/test_contract_conformance.py — PR 10 of
`docs/implementation/basis-core-v0.2-operation-aware-plan.md` (Milestone 3:
"Contract-fixture conformance test suite").

A single, dedicated, exhaustive test module that validates every
operation-aware model built so far (PRs 5-9, 12-15) against every vendored
`valid`/`invalid` example published by all 14 `basis-schemas` v0.2.0
operation-aware contracts under
``tests/fixtures/basis-schemas/v0.2.0/schemas/``, using PR 4's generic
fixture-loading helper (`tests/helpers/operation_aware_contracts.py`) and
discovery helper (`tests/helpers/basis_schemas_snapshot.py`).

This module is test-only and adds no production code. It:
  - registers all 14 vendored operation-aware contracts in one explicit,
    test-local `REGISTRY`, each tagged with its implementation status
    (implemented / future / non-runtime);
  - for **implemented** contracts (`redaction-classification`,
    `reason-code`, `identity-evidence-reference`,
    `adapter-evidence-reference`, `operation-aware-decision-request`,
    `policy-condition`, `policy-rule`, `policy-bundle`,
    `trace-rule-evidence`, `evaluation-trace`), parametrizes construction
    over every vendored `valid` example (must construct and produce the
    exact expected runtime type) and every vendored `invalid` example (must
    be rejected with the precise exception type the corresponding model
    test file already establishes) — every invalid example for every
    implemented contract is enforced, none skipped or deferred;
  - for **future** contracts whose `basis-core` model is scheduled for a
    later roadmap PR (`operation-aware-decision-response`,
    `audit-evidence`), visibly `pytest.mark.skip`s every example with a
    reason naming the exact milestone/PR that will implement it;
  - for contracts that are **intentionally not `basis-core` runtime
    models** (`contract-metadata`, `gateway-audit-event`), visibly skips
    every example with a reason stating the architectural boundary.

No vendored contract or example is silently omitted: `TestRegistryInventory`
proves the registry's contract set matches what is actually discovered on
disk, and that every discovered example (valid and invalid, for every
contract) is represented among the parametrized test cases below.

`policy-bundle` validates through PR 15's explicit pipeline
─────────────────────────────────────────────────────────────
PR 14 registered `policy-bundle` as implemented but could not enforce one
of its own vendored invalid examples ("duplicate rule IDs within one
bundle"): rejecting it requires bundle-level `rule_id`-uniqueness
validation, which `bundle.py`'s `PolicyBundle` model deliberately does not
implement (see that module's docstring, "Deferred to PR 15"). This module
previously deferred (visibly `pytest.mark.skip`ped) that one example via a
now-removed `ConformanceEntry.deferred_invalid_reasons` mechanism.

PR 15 (`basis_core.policy.operation_aware.validation`) adds the explicit
`validate_policy_bundle()` pipeline this suite's `policy-bundle` adapter
now calls, instead of constructing only `PolicyBundle(**example)` — see
`_validate_policy_bundle` below. All 13 vendored `policy-bundle` invalid
examples, including the duplicate-`rule_id` one, are therefore now
actively enforced, and the deferral mechanism (`ConformanceEntry.
deferred_invalid_reasons`, `_BUNDLE_DEFERRED_INVALID_REASONS`,
`_deferred_reason_for`, and `TestDeferredInvalidExamples`) has been
removed as unused complexity — no other contract ever needed it. Because
`validate_policy_bundle` raises either `StructuralPolicyValidationError`
or `SemanticPolicyValidationError`, both subclasses of the single root
`PolicyBundleValidationError`, `policy-bundle`'s `ConformanceEntry.
invalid_exception` is the root type, not `pydantic.ValidationError` — see
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`'s PR 15
entry.

Non-goals (see the roadmap plan's PR 10/PR 14/PR 15 entries and this
repository's `tests/operation_aware/README.md` scope boundaries): no
model not yet implemented is added here; PR 12 registered
`policy-condition` as implemented (structural shape only — no condition
evaluation, operator dispatch, or field-path resolution is implemented or
exercised anywhere in this repository); PR 13 registered `policy-rule` as
implemented (structural shape only — no rule matching, condition
evaluation, or deny precedence is implemented or exercised anywhere in
this repository); PR 14 registered `policy-bundle` as implemented, and
PR 15 completes its enforcement via the explicit validation pipeline
(structural shape and duplicate-`rule_id`/`condition_id` semantic checks
only — no bundle evaluation, no scope-to-request applicability
determination, and no evaluator is implemented or exercised anywhere in
this repository); PR 24 registered `trace-rule-evidence` as implemented
(bounded per-rule trace-evidence shape only — no trace assembly, no
conversion from any internal evaluator result, and no evaluation semantics
of any kind is implemented or exercised anywhere in this repository); PR 25
registered `evaluation-trace` as implemented (bounded, deterministic,
request-level trace shape only, reusing `trace-rule-evidence` for
`rule_evidence` — no trace assembly, no conversion from any internal
evaluator result, and no evaluation semantics of any kind is implemented or
exercised anywhere in this repository); every other not-yet-implemented
contract remains skipped; no compatibility-snapshot fixtures are added (PR
11); no
canonical compatibility-vector (`allow-basic`, `deny-precedence`,
`default-deny`, `not-applicable`, `invalid-policy-bundle`) behavior is
inspected or asserted — this module targets only the 14 contract YAMLs'
own embedded `examples.valid`/`examples.invalid` blocks (canonical-vector
conformance is PR 16, later, separately-scoped roadmap work; the
`invalid-policy-bundle` canonical-vector fixture is instead exercised
directly by `tests/operation_aware/test_policy_validation.py`, per PR 15's
own roadmap entry). `OperationAwareDecisionRequest` construction/type
assertions here are intentionally minimal — full serialization round-trip
coverage remains PR 9's dedicated scope
(`test_decision_request_roundtrip.py`) and is not duplicated here.
"""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Callable

import pytest
from pydantic import ValidationError

from basis_core.audit.operation_aware.evaluation_trace import EvaluationTrace
from basis_core.audit.operation_aware.trace_rule_evidence import TraceRuleEvidence
from basis_core.decisions.operation_aware import OperationAwareDecisionRequest
from basis_core.domain.evidence import AdapterEvidenceReference, IdentityEvidenceReference
from basis_core.domain.operation_aware import (
    OperationAwareDevice,
    OperationAwareEnvironmentContext,
    OperationAwareLocation,
    OperationAwareProtocolContext,
    OperationAwareRiskContext,
    OperationAwareSafetyContext,
)
from basis_core.domain.operation_aware_vocabulary import ReasonCode, RedactionClassification
from basis_core.policy.operation_aware.bundle import PolicyBundle, PolicyBundleScope
from basis_core.policy.operation_aware.condition import PolicyCondition
from basis_core.policy.operation_aware.rule import (
    OperationAwarePolicyMatch,
    OperationAwarePolicyRule,
)
from basis_core.policy.operation_aware.validation import (
    PolicyBundleValidationError,
    validate_policy_bundle,
)
from tests.helpers.basis_schemas_snapshot import list_operation_aware_contracts
from tests.helpers.operation_aware_contracts import (
    load_contract,
    require_mapping_field,
    require_sequence_field,
)

# ══════════════════════════════════════════════════════════════════════════
# Conformance registry
# ══════════════════════════════════════════════════════════════════════════


class ContractStatus:
    """The three conformance categories every vendored contract falls into."""

    IMPLEMENTED = "implemented"
    FUTURE = "future"
    NON_RUNTIME = "non_runtime"


@dataclasses.dataclass(frozen=True)
class ConformanceEntry:
    """One row of the PR 10 conformance registry.

    `validator`/`expected_type`/`invalid_exception` are populated only for
    `ContractStatus.IMPLEMENTED` entries. `skip_reason` is populated only
    for `ContractStatus.FUTURE`/`ContractStatus.NON_RUNTIME` entries and
    must name either the roadmap milestone/PR that will implement the
    contract, or the architectural boundary that keeps it out of
    `basis-core`. `nested_type_checks` is optional and, today, populated
    for `operation-aware-decision-request` (PR 6/PR 7 nested field types)
    and `policy-rule` (its nested `match` field type, PR 13) — it maps an
    optional nested field name to the type it must reconstruct as, for any
    valid example that happens to carry that field.
    """

    name: str
    status: str
    validator: Callable[[object], object] | None = None
    expected_type: type | None = None
    invalid_exception: type[Exception] | None = None
    skip_reason: str | None = None
    nested_type_checks: dict[str, type] | None = None


# ── Validator adapters (implemented contracts only) ─────────────────────
#
# Each adapter is a thin, test-local construction entry point — the same
# boundary a real basis-core consumer would use. No production factory
# function is invented; these simply call the existing PR 5-8 constructors
# directly with the example value the vendored fixture supplies.


def _validate_redaction_classification(example: object) -> RedactionClassification:
    assert isinstance(example, str), (
        f"redaction-classification example must be a bare string, got {type(example).__name__}."
    )
    return RedactionClassification(example)


def _validate_reason_code(example: object) -> ReasonCode:
    assert isinstance(example, str), (
        f"reason-code example must be a bare string, got {type(example).__name__}."
    )
    return ReasonCode(example)


def _validate_identity_evidence_reference(example: object) -> IdentityEvidenceReference:
    assert isinstance(example, dict), (
        f"identity-evidence-reference example must be a bare mapping, got {type(example).__name__}."
    )
    return IdentityEvidenceReference(**example)


def _validate_adapter_evidence_reference(example: object) -> AdapterEvidenceReference:
    assert isinstance(example, dict), (
        f"adapter-evidence-reference example must be a bare mapping, got {type(example).__name__}."
    )
    return AdapterEvidenceReference(**example)


def _validate_operation_aware_request(example: object) -> OperationAwareDecisionRequest:
    assert isinstance(example, dict), (
        "operation-aware-decision-request example must be a bare mapping, got "
        f"{type(example).__name__}."
    )
    return OperationAwareDecisionRequest(**example)


def _validate_policy_condition(example: object) -> PolicyCondition:
    assert isinstance(example, dict), (
        f"policy-condition example must be a bare mapping, got {type(example).__name__}."
    )
    return PolicyCondition(**example)


def _validate_policy_rule(example: object) -> OperationAwarePolicyRule:
    assert isinstance(example, dict), (
        f"policy-rule example must be a bare mapping, got {type(example).__name__}."
    )
    return OperationAwarePolicyRule(**example)


def _validate_policy_bundle(example: object) -> PolicyBundle:
    assert isinstance(example, dict), (
        f"policy-bundle example must be a bare mapping, got {type(example).__name__}."
    )
    return validate_policy_bundle(example)


def _validate_trace_rule_evidence(example: object) -> TraceRuleEvidence:
    assert isinstance(example, dict), (
        f"trace-rule-evidence example must be a bare mapping, got {type(example).__name__}."
    )
    return TraceRuleEvidence(**example)


def _validate_evaluation_trace(example: object) -> EvaluationTrace:
    assert isinstance(example, dict), (
        f"evaluation-trace example must be a bare mapping, got {type(example).__name__}."
    )
    return EvaluationTrace(**example)


# `policy-rule` valid examples that carry a `match` field must reconstruct
# it as the strongly-typed `OperationAwarePolicyMatch`, not a raw dict —
# mirrors `_REQUEST_NESTED_TYPE_CHECKS`'s convention for PR 6/PR 7 nested
# fields on `operation-aware-decision-request`. `conditions` is a list, not
# a single nested field, so it is not represented here; PR 13's own
# dedicated `test_policy_rule.py` fixture-conformance tests assert every
# element of `conditions` reconstructs as `PolicyCondition` directly.
_RULE_NESTED_TYPE_CHECKS: dict[str, type] = {
    "match": OperationAwarePolicyMatch,
}

# `policy-bundle` valid examples that carry a `scope` field must
# reconstruct it as the strongly-typed `PolicyBundleScope`, not a raw
# dict — mirrors `_RULE_NESTED_TYPE_CHECKS`'s convention. `rules` is a
# list, not a single nested field, so — exactly like `policy-rule`'s own
# `conditions` above — it is not represented here; PR 14's own dedicated
# `test_policy_bundle.py` fixture-conformance tests assert every element
# of `rules` reconstructs as `OperationAwarePolicyRule` directly.
_BUNDLE_NESTED_TYPE_CHECKS: dict[str, type] = {
    "scope": PolicyBundleScope,
}


# PR 6 evidence-reference fields and PR 7 context-object fields nested on
# `OperationAwareDecisionRequest`. Asserted strongly typed (not raw dicts)
# for any valid example that happens to carry the field — see
# `TestValidExampleConformance.test_valid_example_conforms`.
_REQUEST_NESTED_TYPE_CHECKS: dict[str, type] = {
    "identity_evidence_reference": IdentityEvidenceReference,
    "adapter_evidence_reference": AdapterEvidenceReference,
    "location": OperationAwareLocation,
    "device": OperationAwareDevice,
    "protocol_context": OperationAwareProtocolContext,
    "safety_context": OperationAwareSafetyContext,
    "environment_context": OperationAwareEnvironmentContext,
    "risk_context": OperationAwareRiskContext,
}


# ── The registry itself ──────────────────────────────────────────────────
#
# Contract order matches `tests/helpers/basis_schemas_snapshot.py`'s
# `OPERATION_AWARE_CONTRACTS` tuple (the same order the roadmap plan
# documents them in), not alphabetical order — this keeps the "implemented
# / future / non-runtime" grouping readable at a glance.

REGISTRY: dict[str, ConformanceEntry] = {
    entry.name: entry
    for entry in (
        # ── Not a basis-core runtime type (publication metadata) ────────
        ConformanceEntry(
            name="contract-metadata",
            status=ContractStatus.NON_RUNTIME,
            skip_reason=(
                "contract-metadata is basis-schemas publication metadata and is "
                "intentionally not a basis-core runtime model"
            ),
        ),
        # ── Implemented (PR 5) ───────────────────────────────────────────
        ConformanceEntry(
            name="redaction-classification",
            status=ContractStatus.IMPLEMENTED,
            validator=_validate_redaction_classification,
            expected_type=RedactionClassification,
            invalid_exception=ValueError,
        ),
        ConformanceEntry(
            name="reason-code",
            status=ContractStatus.IMPLEMENTED,
            validator=_validate_reason_code,
            expected_type=ReasonCode,
            invalid_exception=ValueError,
        ),
        # ── Implemented (PR 6) ───────────────────────────────────────────
        ConformanceEntry(
            name="identity-evidence-reference",
            status=ContractStatus.IMPLEMENTED,
            validator=_validate_identity_evidence_reference,
            expected_type=IdentityEvidenceReference,
            invalid_exception=ValidationError,
        ),
        ConformanceEntry(
            name="adapter-evidence-reference",
            status=ContractStatus.IMPLEMENTED,
            validator=_validate_adapter_evidence_reference,
            expected_type=AdapterEvidenceReference,
            invalid_exception=ValidationError,
        ),
        # ── Implemented (PR 8, composing PR 6/PR 7) ──────────────────────
        ConformanceEntry(
            name="operation-aware-decision-request",
            status=ContractStatus.IMPLEMENTED,
            validator=_validate_operation_aware_request,
            expected_type=OperationAwareDecisionRequest,
            invalid_exception=ValidationError,
            nested_type_checks=_REQUEST_NESTED_TYPE_CHECKS,
        ),
        # ── Implemented (PR 12) ──────────────────────────────────────────
        ConformanceEntry(
            name="policy-condition",
            status=ContractStatus.IMPLEMENTED,
            validator=_validate_policy_condition,
            expected_type=PolicyCondition,
            invalid_exception=ValidationError,
        ),
        # ── Implemented (PR 13) ───────────────────────────────────────────
        ConformanceEntry(
            name="policy-rule",
            status=ContractStatus.IMPLEMENTED,
            validator=_validate_policy_rule,
            expected_type=OperationAwarePolicyRule,
            invalid_exception=ValidationError,
            nested_type_checks=_RULE_NESTED_TYPE_CHECKS,
        ),
        # ── Implemented (PR 14) ───────────────────────────────────────────
        ConformanceEntry(
            name="policy-bundle",
            status=ContractStatus.IMPLEMENTED,
            validator=_validate_policy_bundle,
            expected_type=PolicyBundle,
            invalid_exception=PolicyBundleValidationError,
            nested_type_checks=_BUNDLE_NESTED_TYPE_CHECKS,
        ),
        # ── Implemented (PR 24) ───────────────────────────────────────────
        ConformanceEntry(
            name="trace-rule-evidence",
            status=ContractStatus.IMPLEMENTED,
            validator=_validate_trace_rule_evidence,
            expected_type=TraceRuleEvidence,
            invalid_exception=ValidationError,
        ),
        # ── Implemented (PR 25) ────────────────────────────────────────────
        ConformanceEntry(
            name="evaluation-trace",
            status=ContractStatus.IMPLEMENTED,
            validator=_validate_evaluation_trace,
            expected_type=EvaluationTrace,
            invalid_exception=ValidationError,
        ),
        # ── Future: Milestone 10 (response and AuditEvidence) ────────────
        ConformanceEntry(
            name="operation-aware-decision-response",
            status=ContractStatus.FUTURE,
            skip_reason=(
                "basis-core operation-aware-decision-response model is scheduled for "
                "Milestone 10 / PR 29"
            ),
        ),
        ConformanceEntry(
            name="audit-evidence",
            status=ContractStatus.FUTURE,
            skip_reason=("basis-core audit-evidence model is scheduled for Milestone 10 / PR 30"),
        ),
        # ── Outside the basis-core runtime boundary ──────────────────────
        ConformanceEntry(
            name="gateway-audit-event",
            status=ContractStatus.NON_RUNTIME,
            skip_reason=(
                "gateway-audit-event is owned by basis-gateway and is intentionally not "
                "implemented as a basis-core runtime model"
            ),
        ),
    )
}


# ══════════════════════════════════════════════════════════════════════════
# Fixture discovery and example loading (reuses PR 4's helpers only)
# ══════════════════════════════════════════════════════════════════════════

#: Contract directory names actually present on disk today — the source of
#: truth this suite is checked against, not merely `REGISTRY`'s keys.
_DISCOVERED_CONTRACTS: tuple[str, ...] = tuple(list_operation_aware_contracts())


def _root_section_name(contract_name: str) -> str:
    """The kebab-case contract name's snake_case top-level YAML key.

    Every pinned contract publishes exactly one non-`contract` top-level
    mapping key, named by replacing `-` with `_` in the contract's own
    name (e.g. ``"operation-aware-decision-request"`` ->
    ``"operation_aware_decision_request"``) — verified directly against
    all 14 vendored files during this module's authoring.
    """
    return contract_name.replace("-", "_")


def _load_examples(contract_name: str) -> tuple[list[object], list[object]]:
    """Load the `valid`/`invalid` example sequences for one vendored
    contract, via PR 4's `load_contract` + `require_*` helpers only."""
    document = load_contract(contract_name)
    section = require_mapping_field(
        document, _root_section_name(contract_name), context=contract_name
    )
    examples = require_mapping_field(
        section, "examples", context=f"{contract_name}.{_root_section_name(contract_name)}"
    )
    valid = require_sequence_field(examples, "valid", context=f"{contract_name}.examples")
    invalid = require_sequence_field(examples, "invalid", context=f"{contract_name}.examples")
    return valid, invalid


#: `{contract_name: (valid_examples, invalid_examples)}` for every
#: contract actually discovered on disk.
_EXAMPLES_BY_CONTRACT: dict[str, tuple[list[object], list[object]]] = {
    name: _load_examples(name) for name in _DISCOVERED_CONTRACTS
}


# ══════════════════════════════════════════════════════════════════════════
# Pytest ID / example-shape helpers
# ══════════════════════════════════════════════════════════════════════════

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slugify(text: str) -> str:
    slug = _SLUG_RE.sub("-", text.strip().lower()).strip("-")
    return slug or "example"


def _valid_example_label(example: object, index: int) -> str:
    """A short, readable pytest-ID fragment for one vendored valid example.

    Vendored valid examples carry no uniform "description" field, so this
    prefers whichever identifier-shaped field the example itself carries
    (bare scalar value, or one of a handful of common identifier field
    names on a bare mapping), falling back to the example's position only
    when no better label is available.
    """
    if isinstance(example, str):
        return _slugify(example) if example else f"empty-{index}"
    if isinstance(example, dict):
        for key in (
            "name",
            "reference_id",
            "request_id",
            "event_id",
            "rule_id",
            "condition_id",
            "bundle_id",
            "id",
        ):
            value = example.get(key)
            if isinstance(value, str) and value:
                return _slugify(value)
    return f"example-{index}"


def _invalid_example_label(entry: object, index: int) -> str:
    """A short, readable pytest-ID fragment for one vendored invalid
    example, preferring its documented `reason` when present (the common
    `{"reason": ..., "value": ...}` shape) or the bare scalar itself."""
    if isinstance(entry, dict):
        reason = entry.get("reason")
        if isinstance(reason, str) and reason:
            return _slugify(reason)
    if isinstance(entry, str):
        return _slugify(entry) if entry else f"empty-{index}"
    return f"example-{index}"


def _invalid_example_value(entry: object) -> object:
    """The actual construction input for one vendored invalid example.

    Most contracts wrap invalid examples as `{"reason": ..., "value":
    ...}`; a few (e.g. `reason-code`) publish bare invalid scalars with no
    wrapper. Both shapes are handled generically, with no per-contract
    branching.
    """
    if isinstance(entry, dict) and "value" in entry and "reason" in entry:
        return entry["value"]
    return entry


# ══════════════════════════════════════════════════════════════════════════
# Parametrized case construction
# ══════════════════════════════════════════════════════════════════════════


@dataclasses.dataclass(frozen=True)
class _CaseMeta:
    """Plain-data record of one generated case, independent of pytest's
    `ParameterSet` internals — used by the inventory-completeness tests
    below so they don't need to introspect `pytest.param` objects."""

    contract: str
    status: str


def _build_cases(
    kind: str,
) -> tuple[list[object], list[_CaseMeta]]:
    """Build the parametrized cases (and parallel plain-data metadata) for
    either `"valid"` or `"invalid"` examples, across every contract
    actually discovered on disk.

    A contract discovered on disk but absent from `REGISTRY` (a renamed or
    newly-vendored contract nobody has registered yet) contributes no
    cases here — that mismatch is a hard failure surfaced separately by
    `TestRegistryInventory.test_registry_matches_discovered_contracts`,
    rather than a silent omission or a confusing collection-time crash.

    Every example for an `IMPLEMENTED` contract is enforced (PR 15 removed
    the one deferral this suite previously carried for `policy-bundle`'s
    duplicate-`rule_id` example — see this module's docstring).
    """
    params: list[object] = []
    meta: list[_CaseMeta] = []
    for contract in _DISCOVERED_CONTRACTS:
        entry = REGISTRY.get(contract)
        if entry is None:
            continue
        valid_examples, invalid_examples = _EXAMPLES_BY_CONTRACT[contract]
        examples = valid_examples if kind == "valid" else invalid_examples
        for index, raw in enumerate(examples):
            label = (
                _valid_example_label(raw, index)
                if kind == "valid"
                else _invalid_example_label(raw, index)
            )
            marks = []
            if entry.status == ContractStatus.IMPLEMENTED:
                test_id = f"{contract}-{kind}-{label}"
            else:
                test_id = f"{contract}-skipped-{kind}-{label}"
                assert entry.skip_reason
                marks.append(pytest.mark.skip(reason=entry.skip_reason))
            params.append(pytest.param(contract, raw, id=test_id, marks=marks))
            meta.append(_CaseMeta(contract=contract, status=entry.status))
    return params, meta


_VALID_PARAMS, _VALID_META = _build_cases("valid")
_INVALID_PARAMS, _INVALID_META = _build_cases("invalid")


# ══════════════════════════════════════════════════════════════════════════
# Registry self-consistency
# ══════════════════════════════════════════════════════════════════════════


class TestRegistryConsistency:
    """The registry itself must be internally coherent before it can be
    trusted to drive the conformance cases below."""

    @pytest.mark.parametrize("contract", sorted(REGISTRY))
    def test_registry_entry_is_well_formed(self, contract: str) -> None:
        entry = REGISTRY[contract]
        if entry.status == ContractStatus.IMPLEMENTED:
            assert entry.validator is not None, f"{contract}: implemented but has no validator"
            assert entry.expected_type is not None, (
                f"{contract}: implemented but has no expected_type"
            )
            assert entry.invalid_exception is not None, (
                f"{contract}: implemented but has no invalid_exception"
            )
        else:
            assert entry.skip_reason, f"{contract}: not implemented but has no skip_reason"
            assert entry.validator is None, f"{contract}: not implemented but declares a validator"


# ══════════════════════════════════════════════════════════════════════════
# Inventory completeness — no contract or example may disappear silently
# ══════════════════════════════════════════════════════════════════════════


class TestRegistryInventory:
    def test_registry_matches_discovered_contracts(self) -> None:
        """Every vendored operation-aware contract directory must have
        exactly one registry entry, and vice versa. A contract added,
        removed, or renamed on disk without a matching registry update
        fails here, not silently."""
        discovered = set(_DISCOVERED_CONTRACTS)
        registered = set(REGISTRY)
        assert discovered == registered, (
            f"Registry/discovery mismatch. "
            f"Discovered but not registered: {sorted(discovered - registered)}. "
            f"Registered but not discovered: {sorted(registered - discovered)}."
        )

    def test_fourteen_contracts_are_discovered(self) -> None:
        # A supplementary count check — discovery (above) is the primary
        # completeness mechanism; this only guards against a
        # simultaneous, coincidentally-matching add+remove.
        assert len(_DISCOVERED_CONTRACTS) == 14

    def test_every_contract_has_at_least_one_valid_and_invalid_example(self) -> None:
        for contract in _DISCOVERED_CONTRACTS:
            valid_examples, invalid_examples = _EXAMPLES_BY_CONTRACT[contract]
            assert len(valid_examples) >= 1, f"{contract}: no vendored valid examples found"
            assert len(invalid_examples) >= 1, f"{contract}: no vendored invalid examples found"


class TestExampleInventory:
    def test_every_discovered_valid_example_is_parametrized(self) -> None:
        total_discovered = sum(len(_EXAMPLES_BY_CONTRACT[c][0]) for c in _DISCOVERED_CONTRACTS)
        total_registered = sum(1 for c in _DISCOVERED_CONTRACTS if c in REGISTRY)
        assert total_registered == len(_DISCOVERED_CONTRACTS), (
            "one or more discovered contracts are missing from REGISTRY; see "
            "TestRegistryInventory.test_registry_matches_discovered_contracts"
        )
        assert len(_VALID_PARAMS) == total_discovered
        assert len(_VALID_META) == total_discovered

    def test_every_discovered_invalid_example_is_parametrized(self) -> None:
        total_discovered = sum(len(_EXAMPLES_BY_CONTRACT[c][1]) for c in _DISCOVERED_CONTRACTS)
        assert len(_INVALID_PARAMS) == total_discovered
        assert len(_INVALID_META) == total_discovered

    def test_every_contract_contributes_at_least_one_of_each_case(self) -> None:
        valid_contracts = {m.contract for m in _VALID_META}
        invalid_contracts = {m.contract for m in _INVALID_META}
        assert valid_contracts == set(_DISCOVERED_CONTRACTS)
        assert invalid_contracts == set(_DISCOVERED_CONTRACTS)


# ══════════════════════════════════════════════════════════════════════════
# Conformance: implemented contracts must accept every valid example and
# reject every invalid example; future/non-runtime contracts are visibly
# skipped with an explicit reason (never filtered out before
# parametrization).
# ══════════════════════════════════════════════════════════════════════════


class TestValidExampleConformance:
    @pytest.mark.parametrize(("contract", "example"), _VALID_PARAMS)
    def test_valid_example_conforms(self, contract: str, example: object) -> None:
        entry = REGISTRY[contract]
        assert entry.validator is not None
        assert entry.expected_type is not None

        result = entry.validator(example)

        assert type(result) is entry.expected_type

        if entry.nested_type_checks and isinstance(example, dict):
            for field_name, expected_nested_type in entry.nested_type_checks.items():
                if field_name in example:
                    nested_value = getattr(result, field_name)
                    assert type(nested_value) is expected_nested_type, (
                        f"{contract}: expected {field_name!r} to reconstruct as "
                        f"{expected_nested_type.__name__}, got "
                        f"{type(nested_value).__name__}"
                    )


class TestInvalidExampleConformance:
    @pytest.mark.parametrize(("contract", "raw_entry"), _INVALID_PARAMS)
    def test_invalid_example_is_rejected(self, contract: str, raw_entry: object) -> None:
        entry = REGISTRY[contract]
        assert entry.validator is not None
        assert entry.invalid_exception is not None

        value = _invalid_example_value(raw_entry)
        with pytest.raises(entry.invalid_exception):
            entry.validator(value)


class TestPolicyBundleAllInvalidExamplesEnforced:
    """PR 15 activated enforcement of the one `policy-bundle` invalid
    example ("duplicate rule IDs within one bundle") that PR 14 could not
    yet reject — see this module's docstring. All 13 vendored
    `policy-bundle` invalid examples are enforced identically now; none
    remain deferred or skipped."""

    def test_policy_bundle_has_thirteen_invalid_examples_all_enforced(self) -> None:
        _, invalid_examples = _EXAMPLES_BY_CONTRACT["policy-bundle"]
        assert len(invalid_examples) == 13
        policy_bundle_meta = [m for m in _INVALID_META if m.contract == "policy-bundle"]
        assert len(policy_bundle_meta) == 13

    def test_duplicate_rule_id_example_is_actively_rejected(self) -> None:
        _, invalid_examples = _EXAMPLES_BY_CONTRACT["policy-bundle"]
        (entry,) = [
            ex
            for ex in invalid_examples
            if isinstance(ex, dict) and ex.get("reason") == "duplicate rule IDs within one bundle"
        ]
        registry_entry = REGISTRY["policy-bundle"]
        assert registry_entry.validator is not None
        assert registry_entry.invalid_exception is not None
        with pytest.raises(registry_entry.invalid_exception):
            registry_entry.validator(_invalid_example_value(entry))


# ══════════════════════════════════════════════════════════════════════════
# PR 7 nested context models, exercised through PR C request examples
# ══════════════════════════════════════════════════════════════════════════


class TestNestedContextModelsExercisedThroughRequestFixtures:
    """Roadmap-required check: the vendored `operation-aware-decision-
    request` valid examples that carry PR 7's six context objects (and PR
    6's two evidence references) must reconstruct them as the correct
    strongly-typed classes, not raw dicts. This does not re-run PR 7's own
    exhaustive independently-optional-subfield matrix — it only proves
    fixture-to-model conformance for whichever nested fields the vendored
    examples happen to carry.
    """

    def test_at_least_one_vendored_valid_example_carries_every_nested_field(self) -> None:
        # Guards against a future fixture change silently dropping the
        # only example(s) that exercise a given nested field: if this
        # starts failing, `test_valid_example_conforms`'s nested-type
        # assertions for that field would otherwise stop running at all.
        valid_examples, _ = _EXAMPLES_BY_CONTRACT["operation-aware-decision-request"]
        fields_seen: set[str] = set()
        for example in valid_examples:
            assert isinstance(example, dict)
            fields_seen.update(example.keys())
        for field_name in _REQUEST_NESTED_TYPE_CHECKS:
            assert field_name in fields_seen, (
                f"no vendored valid operation-aware-decision-request example carries "
                f"{field_name!r}; nested-type conformance for it is not exercised"
            )
