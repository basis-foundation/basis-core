"""
tests/operation_aware/test_contract_loading.py — contract-loading tests for
the pinned `basis-schemas` v0.2.0 operation-aware contracts (Milestone 1,
PR 4 of `docs/implementation/basis-core-v0.2-operation-aware-plan.md`).

These tests prove that every one of the 14 pinned contract YAMLs is
parseable, has a mapping root, carries structurally valid `contract:`
metadata, and declares a `name` matching its own inventory entry — using
only the generic loader and structural helpers in
`tests/helpers/operation_aware_contracts.py`. They intentionally assert
nothing about any contract's business semantics (patterns, enums,
cross-field rules, or the operation-aware domain model those contracts will
eventually back) — that is later, separate roadmap work.
"""

from __future__ import annotations

import copy

import pytest

from tests.helpers.basis_schemas_snapshot import OPERATION_AWARE_CONTRACTS
from tests.helpers.operation_aware_contracts import (
    load_contract,
    require_optional_field,
    require_string_field,
    validate_contract_metadata,
)

# ── Every pinned contract loads and has a mapping root ──────────────────


@pytest.mark.parametrize("contract_name", OPERATION_AWARE_CONTRACTS)
def test_every_pinned_contract_loads_successfully(contract_name: str) -> None:
    document = load_contract(contract_name)
    assert isinstance(document, dict)
    assert document, f"Contract {contract_name!r} loaded an empty mapping."


# ── Structurally valid contract metadata ─────────────────────────────────


@pytest.mark.parametrize("contract_name", OPERATION_AWARE_CONTRACTS)
def test_every_pinned_contract_has_structurally_valid_metadata(contract_name: str) -> None:
    document = load_contract(contract_name)
    metadata = validate_contract_metadata(document, context=f"contract {contract_name!r}")
    assert isinstance(metadata, dict)


@pytest.mark.parametrize("contract_name", OPERATION_AWARE_CONTRACTS)
def test_contract_name_field_matches_its_own_inventory_name(contract_name: str) -> None:
    document = load_contract(contract_name)
    metadata = validate_contract_metadata(document, context=f"contract {contract_name!r}")
    name = require_string_field(metadata, "name", context=f"contract {contract_name!r}.contract")
    assert name == contract_name


@pytest.mark.parametrize("contract_name", OPERATION_AWARE_CONTRACTS)
def test_depends_on_field_is_structurally_valid_when_present(contract_name: str) -> None:
    document = load_contract(contract_name)
    metadata = validate_contract_metadata(document, context=f"contract {contract_name!r}")
    depends_on = require_optional_field(
        metadata,
        "depends_on",
        expected_type=list,
        context=f"contract {contract_name!r}.contract",
    )
    if depends_on is not None:
        assert all(isinstance(item, str) for item in depends_on)


# ── Determinism and non-mutation ─────────────────────────────────────────


@pytest.mark.parametrize("contract_name", OPERATION_AWARE_CONTRACTS)
def test_repeated_loading_of_the_same_contract_is_deterministic(contract_name: str) -> None:
    first = load_contract(contract_name)
    second = load_contract(contract_name)
    assert first == second


def test_validation_helpers_do_not_mutate_the_loaded_document() -> None:
    document = load_contract("policy-bundle")
    before = copy.deepcopy(document)

    validate_contract_metadata(document, context="contract 'policy-bundle'")

    assert document == before, "validate_contract_metadata must not mutate its input."


def test_mutating_a_returned_document_does_not_affect_a_fresh_load() -> None:
    """This loader holds no cache: mutating a caller's copy of a loaded
    document must have no effect on a subsequent, independent load."""
    first = load_contract("policy-bundle")
    first["contract"]["name"] = "tampered"  # type: ignore[index]

    second = load_contract("policy-bundle")
    assert second["contract"]["name"] == "policy-bundle"  # type: ignore[index]
