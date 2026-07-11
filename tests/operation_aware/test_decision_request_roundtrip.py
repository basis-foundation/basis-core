"""
tests/operation_aware/test_decision_request_roundtrip.py — request-level
structural conformance and JSON serialization round-trip tests for
`basis_core.decisions.operation_aware.OperationAwareDecisionRequest`
(Milestone 2, PR 9 of
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`: "Request-level
structural validation & serialization round-trip tests").

This module closes out Milestone 2. It is test-only: no production model
code is added or changed by this PR. PR 8
(`tests/operation_aware/test_decision_request.py`) already covers
construction, defaults, required-field enforcement, pattern/enum validation,
nested composition, and unknown-field rejection — this file does not repeat
that coverage. Its one, exhaustively-applied invariant is:

    valid fixture
        -> OperationAwareDecisionRequest.model_validate(...)
        -> model_dump(mode="json")
        -> real JSON encode/decode (json.dumps / json.loads)
        -> OperationAwareDecisionRequest.model_validate(...)
        -> equal model, with a second JSON-mode dump equal to the first

applied to every valid example vendored by the `operation-aware-decision-
request` contract (PR C) and to the operation-aware request fixture of every
one of the 5 pinned canonical compatibility-vector scenarios (PR 4).

Scope boundaries carried forward from PR 8's module docstring apply here too:
this file evaluates no policy, matches no conditions, inspects no evaluation
trace, decision response, or audit evidence, and asserts no scenario outcome
(allow / deny / not_applicable / failed) for any canonical scenario — the
canonical request fixture is used only as a realistic request-serialization
fixture. Contract-wide conformance across every operation-aware model
(PR 10) and compatibility-snapshot scaffolding (PR 11) are later, separately
scoped roadmap work and are not started here.
"""

from __future__ import annotations

import json
import re
from datetime import datetime

import pytest
from pydantic import ValidationError

from basis_core.decisions.operation_aware import (
    OperationAwareDecisionRequest,
    OperationIntent,
)
from basis_core.domain.evidence import AdapterEvidenceReference, IdentityEvidenceReference
from basis_core.domain.operation_aware import (
    OperationAwareDevice,
    OperationAwareEnvironmentContext,
    OperationAwareLocation,
    OperationAwareProtocolContext,
    OperationAwareRiskContext,
    OperationAwareSafetyContext,
)
from tests.helpers.basis_schemas_snapshot import COMPATIBILITY_SCENARIOS
from tests.helpers.operation_aware_contracts import (
    load_contract,
    load_scenario_artifact,
    require_mapping_field,
    require_sequence_field,
)

_CONTRACT_NAME = "operation-aware-decision-request"
_ROOT_SECTION = "operation_aware_decision_request"

# Descriptive labels for the vendored PR C valid examples, in the order the
# contract documents them (see the numbered comments in
# tests/fixtures/basis-schemas/v0.2.0/schemas/operation-aware-decision-request/
# operation-aware-decision-request.yaml's examples.valid list: "1. Minimal
# request...", "2. Subject-rich request...", "3. OT operation-rich
# request...", "4. Full contextual request..."). These labels exist only to
# make test IDs readable; the number of examples exercised is always
# discovered from the vendored contract (see `_pr_c_valid_examples` below),
# never hard-coded — an example beyond this tuple's length still runs, just
# under a positional fallback ID.
_PR_C_VALID_LABELS: tuple[str, ...] = (
    "minimal",
    "subject-rich",
    "operation-rich",
    "full-context",
)


def _slug(text: str) -> str:
    """Turn a free-form fixture 'reason' string into a short, readable test
    ID fragment (lowercase, hyphen-separated, no punctuation)."""
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug[:40]


def _load_root_section() -> dict[str, object]:
    document = load_contract(_CONTRACT_NAME)
    return require_mapping_field(document, _ROOT_SECTION, context=_CONTRACT_NAME)


def _pr_c_valid_examples() -> list[tuple[str, dict[str, object]]]:
    """Every vendored PR C valid request example, paired with a readable
    test ID. Count is discovered from the vendored contract, not asserted
    here as a fixed number."""
    root = _load_root_section()
    examples = require_mapping_field(root, "examples", context=_ROOT_SECTION)
    valid = require_sequence_field(examples, "valid", context=f"{_ROOT_SECTION}.examples")
    labeled: list[tuple[str, dict[str, object]]] = []
    for index, example in enumerate(valid):
        assert isinstance(example, dict), (
            f"{_ROOT_SECTION}.examples.valid[{index}]: expected a mapping, "
            f"got {type(example).__name__}."
        )
        label = _PR_C_VALID_LABELS[index] if index < len(_PR_C_VALID_LABELS) else str(index)
        labeled.append((f"pr-c-{label}", example))
    return labeled


def _pr_c_invalid_examples() -> list[tuple[str, dict[str, object]]]:
    """Every vendored PR C invalid example's `value` mapping, paired with a
    readable test ID derived from its documented `reason`."""
    root = _load_root_section()
    examples = require_mapping_field(root, "examples", context=_ROOT_SECTION)
    invalid = require_sequence_field(examples, "invalid", context=f"{_ROOT_SECTION}.examples")
    labeled: list[tuple[str, dict[str, object]]] = []
    for index, entry in enumerate(invalid):
        assert isinstance(entry, dict)
        value = entry["value"]
        assert isinstance(value, dict)
        reason = entry.get("reason", "")
        label = f"pr-c-invalid-{index}-{_slug(str(reason))}" if reason else f"pr-c-invalid-{index}"
        labeled.append((label, value))
    return labeled


def _canonical_request_fixtures() -> list[tuple[str, dict[str, object]]]:
    """The operation-aware request fixture from every one of the 5 pinned
    canonical compatibility-vector scenarios (PR 4's
    `COMPATIBILITY_SCENARIOS`), paired with a readable test ID derived from
    the scenario directory name. Only the `request` artifact is loaded for
    each scenario — no policy bundle, trace, response, or audit evidence.
    """
    labeled: list[tuple[str, dict[str, object]]] = []
    for scenario in COMPATIBILITY_SCENARIOS:
        request = load_scenario_artifact(scenario, "request")
        assert isinstance(request, dict), (
            f"canonical scenario {scenario!r} request fixture: expected a mapping, "
            f"got {type(request).__name__}."
        )
        labeled.append((f"canonical-{scenario}", request))
    return labeled


def _first_example_with_field(
    examples: list[tuple[str, dict[str, object]]], field: str
) -> tuple[str, dict[str, object]]:
    """Return the first (label, example) pair whose fixture includes
    `field`, discovered dynamically rather than assumed to live at a fixed
    index."""
    for label, example in examples:
        if field in example:
            return label, example
    pytest.fail(f"No fixture among {[label for label, _ in examples]} includes field {field!r}.")
    raise AssertionError("unreachable")  # pragma: no cover


# All valid request fixtures this PR exercises the full round trip against:
# every vendored PR C valid example, plus every canonical-vector request.
_ALL_VALID_FIXTURES = _pr_c_valid_examples() + _canonical_request_fixtures()
_ALL_VALID_IDS = [label for label, _ in _ALL_VALID_FIXTURES]
_ALL_VALID_VALUES = [example for _, example in _ALL_VALID_FIXTURES]

_PR_C_INVALID_FIXTURES = _pr_c_invalid_examples()
_PR_C_INVALID_IDS = [label for label, _ in _PR_C_INVALID_FIXTURES]
_PR_C_INVALID_VALUES = [value for _, value in _PR_C_INVALID_FIXTURES]


# ══════════════════════════════════════════════════════════════════════════
# Core round-trip procedure — every valid PR C example and canonical request
# ══════════════════════════════════════════════════════════════════════════


class TestFullRoundTrip:
    @pytest.mark.parametrize("fixture", _ALL_VALID_VALUES, ids=_ALL_VALID_IDS)
    def test_serialize_deserialize_equality_round_trip(self, fixture: dict[str, object]) -> None:
        # Step 1 — construct.
        original = OperationAwareDecisionRequest.model_validate(fixture)

        # Step 2 — produce JSON-compatible data, exercising mode="json"
        # explicitly (not the bare model_dump()).
        first_dump = original.model_dump(mode="json")

        # Step 3 — prove the output is real JSON data: no datetime objects,
        # enum instances, tuples, or other Python-only values survive a
        # real json.dumps/json.loads round trip through the stdlib boundary,
        # with no custom encoder.
        encoded = json.dumps(first_dump)
        decoded = json.loads(encoded)
        assert isinstance(decoded, dict)

        # Step 4 — reconstruct from the JSON-decoded mapping.
        restored = OperationAwareDecisionRequest.model_validate(decoded)

        # Step 5 — semantic equality, and the reconstructed object remains
        # exactly OperationAwareDecisionRequest (not a subclass, not a dict).
        assert type(restored) is OperationAwareDecisionRequest
        assert restored == original

        # Repeated JSON-mode dump of the reconstructed model is stable:
        # deterministic normalized serialization for the same model state.
        second_dump = restored.model_dump(mode="json")
        assert second_dump == first_dump


# ══════════════════════════════════════════════════════════════════════════
# Invalid PR C examples: exhaustive inventory accounted for, not round-tripped
# ══════════════════════════════════════════════════════════════════════════


class TestInvalidExamplesRemainRejected:
    """An invalid request cannot participate in a round trip — it never
    successfully constructs. `test_decision_request.py` (PR 8) already
    proves every vendored invalid example is rejected; this parametrized
    check exists only so the complete PR C fixture inventory (valid +
    invalid) is visibly accounted for within this PR's own module, without
    duplicating PR 8's field-by-field invalid-example test."""

    @pytest.mark.parametrize("value", _PR_C_INVALID_VALUES, ids=_PR_C_INVALID_IDS)
    def test_invalid_example_still_fails_construction(self, value: dict[str, object]) -> None:
        with pytest.raises(ValidationError):
            OperationAwareDecisionRequest.model_validate(value)


# ══════════════════════════════════════════════════════════════════════════
# Serialization expectations: datetime
# ══════════════════════════════════════════════════════════════════════════


class TestDatetimeSerialization:
    def test_evaluation_time_round_trips_as_equivalent_tz_aware_datetime(self) -> None:
        _, example = _first_example_with_field(_ALL_VALID_FIXTURES, "evaluation_time")

        original = OperationAwareDecisionRequest.model_validate(example)
        assert original.evaluation_time is not None
        assert original.evaluation_time.tzinfo is not None

        dumped = original.model_dump(mode="json")
        # JSON-mode output must be a plain JSON string, not a datetime object.
        assert isinstance(dumped["evaluation_time"], str)

        decoded = json.loads(json.dumps(dumped))
        restored = OperationAwareDecisionRequest.model_validate(decoded)

        assert isinstance(restored.evaluation_time, datetime)
        assert restored.evaluation_time.tzinfo is not None
        # Semantic equality, not textual/spelling equality (no "Z" vs.
        # "+00:00" normalization is required or asserted).
        assert restored.evaluation_time == original.evaluation_time
        assert restored == original


# ══════════════════════════════════════════════════════════════════════════
# Serialization expectations: enums (operation_intent)
# ══════════════════════════════════════════════════════════════════════════


class TestEnumSerialization:
    def test_operation_intent_round_trips_as_contract_string_value(self) -> None:
        _, example = _first_example_with_field(_ALL_VALID_FIXTURES, "operation_intent")

        original = OperationAwareDecisionRequest.model_validate(example)
        assert isinstance(original.operation_intent, OperationIntent)

        dumped = original.model_dump(mode="json")
        # JSON-mode output must contain the contract string value, never a
        # Python enum instance.
        assert isinstance(dumped["operation_intent"], str)
        assert not isinstance(dumped["operation_intent"], OperationIntent)
        assert dumped["operation_intent"] == original.operation_intent.value

        decoded = json.loads(json.dumps(dumped))
        restored = OperationAwareDecisionRequest.model_validate(decoded)

        assert isinstance(restored.operation_intent, OperationIntent)
        assert restored.operation_intent is original.operation_intent
        assert restored == original


# ══════════════════════════════════════════════════════════════════════════
# Nested models survive the request-level JSON boundary
# ══════════════════════════════════════════════════════════════════════════


class TestNestedModelReconstruction:
    """Proves PR 6/PR 7 nested types survive the request-level JSON
    round trip as strongly typed objects, not raw dicts. Does not duplicate
    PR 6/PR 7's own exhaustive nested-field validation."""

    def _round_tripped(self, example: dict[str, object]) -> OperationAwareDecisionRequest:
        original = OperationAwareDecisionRequest.model_validate(example)
        dumped = original.model_dump(mode="json")
        decoded = json.loads(json.dumps(dumped))
        return OperationAwareDecisionRequest.model_validate(decoded)

    def test_identity_evidence_reference_reconstructs_typed(self) -> None:
        _, example = _first_example_with_field(_ALL_VALID_FIXTURES, "identity_evidence_reference")
        restored = self._round_tripped(example)
        assert isinstance(restored.identity_evidence_reference, IdentityEvidenceReference)

    def test_adapter_evidence_reference_reconstructs_typed(self) -> None:
        _, example = _first_example_with_field(_ALL_VALID_FIXTURES, "adapter_evidence_reference")
        restored = self._round_tripped(example)
        assert isinstance(restored.adapter_evidence_reference, AdapterEvidenceReference)

    def test_location_reconstructs_typed(self) -> None:
        _, example = _first_example_with_field(_ALL_VALID_FIXTURES, "location")
        restored = self._round_tripped(example)
        assert isinstance(restored.location, OperationAwareLocation)

    def test_device_reconstructs_typed(self) -> None:
        _, example = _first_example_with_field(_ALL_VALID_FIXTURES, "device")
        restored = self._round_tripped(example)
        assert isinstance(restored.device, OperationAwareDevice)

    def test_protocol_context_reconstructs_typed(self) -> None:
        _, example = _first_example_with_field(_ALL_VALID_FIXTURES, "protocol_context")
        restored = self._round_tripped(example)
        assert isinstance(restored.protocol_context, OperationAwareProtocolContext)

    def test_safety_context_reconstructs_typed(self) -> None:
        _, example = _first_example_with_field(_ALL_VALID_FIXTURES, "safety_context")
        restored = self._round_tripped(example)
        assert isinstance(restored.safety_context, OperationAwareSafetyContext)

    def test_environment_context_reconstructs_typed(self) -> None:
        _, example = _first_example_with_field(_ALL_VALID_FIXTURES, "environment_context")
        restored = self._round_tripped(example)
        assert isinstance(restored.environment_context, OperationAwareEnvironmentContext)

    def test_risk_context_reconstructs_typed(self) -> None:
        _, example = _first_example_with_field(_ALL_VALID_FIXTURES, "risk_context")
        restored = self._round_tripped(example)
        assert isinstance(restored.risk_context, OperationAwareRiskContext)


# ══════════════════════════════════════════════════════════════════════════
# Collections and mappings preserved, unmodified
# ══════════════════════════════════════════════════════════════════════════


class TestCollectionAndMappingPreservation:
    def test_subject_roles_preserved_without_reordering_or_dedup(self) -> None:
        _, example = _first_example_with_field(_ALL_VALID_FIXTURES, "subject_roles")

        original = OperationAwareDecisionRequest.model_validate(example)
        dumped = original.model_dump(mode="json")
        assert isinstance(dumped["subject_roles"], list)

        decoded = json.loads(json.dumps(dumped))
        restored = OperationAwareDecisionRequest.model_validate(decoded)

        assert restored.subject_roles == original.subject_roles
        assert list(restored.subject_roles) == list(example["subject_roles"])  # type: ignore[arg-type]

    def test_subject_attrs_preserved(self) -> None:
        _, example = _first_example_with_field(_ALL_VALID_FIXTURES, "subject_attrs")

        original = OperationAwareDecisionRequest.model_validate(example)
        dumped = original.model_dump(mode="json")
        assert isinstance(dumped["subject_attrs"], dict)

        decoded = json.loads(json.dumps(dumped))
        restored = OperationAwareDecisionRequest.model_validate(decoded)

        assert restored.subject_attrs == original.subject_attrs
        assert restored.subject_attrs == example["subject_attrs"]


# ══════════════════════════════════════════════════════════════════════════
# Sanity: fixture inventory this module actually exercised
# ══════════════════════════════════════════════════════════════════════════


class TestFixtureInventoryDiscovered:
    """These are not arbitrary hard-coded counts: they are lower bounds
    proving the loaders actually discovered vendored content (a silently
    empty parametrize list would otherwise make every test above vacuously
    pass)."""

    def test_at_least_four_pr_c_valid_examples_discovered(self) -> None:
        assert len(_pr_c_valid_examples()) >= 4

    def test_at_least_ten_pr_c_invalid_examples_discovered(self) -> None:
        assert len(_pr_c_invalid_examples()) >= 10

    def test_exactly_five_canonical_scenarios_discovered(self) -> None:
        fixtures = _canonical_request_fixtures()
        assert len(fixtures) == 5
        assert {label for label, _ in fixtures} == {
            f"canonical-{scenario}" for scenario in COMPATIBILITY_SCENARIOS
        }
