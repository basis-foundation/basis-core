"""
tests/operation_aware/test_scaffold.py — infrastructure-only scaffold tests
for the `tests/operation_aware/` package (Milestone 0, PR 3 of
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`).

These tests prove that the dedicated operation-aware test package exists,
is discovered by pytest, can reach the pinned `basis-schemas` v0.2.0 fixture
foundation through the existing test-only helper module, and stays isolated
from both nonexistent production operation-aware code and the `basis_core`
public API.

This module intentionally contains no domain-model, policy, trace, audit, or
evaluator assertions — that is later, separate roadmap work. It also adds no
new fixture-loading behavior and parses no YAML; it only proves that the
helpers established by the fixture-foundation PR are reachable from this new
package.
"""

from __future__ import annotations

import importlib
import importlib.util
import sys
from pathlib import Path

from tests.helpers.basis_schemas_snapshot import (
    COMPATIBILITY_SCENARIOS,
    OPERATION_AWARE_CONTRACTS,
    get_scenario_artifact,
    get_schema_path,
    list_compatibility_scenarios,
    list_operation_aware_contracts,
)

# ── Package discovery ───────────────────────────────────────────────────────


def test_this_module_is_collected_from_the_operation_aware_package() -> None:
    """A meaningful (not merely `assert True`) proof that pytest discovered
    and executed a test *inside* `tests/operation_aware/`: the running
    module's own dotted name and file location must resolve into this
    package, not into the flat `tests/` tree."""
    assert __name__ == "tests.operation_aware.test_scaffold"
    assert Path(__file__).parent.name == "operation_aware"
    assert Path(__file__).parent.parent.name == "tests"


def test_operation_aware_package_is_importable() -> None:
    """The package marker imports cleanly and carries no executable side
    effects worth noting beyond its docstring."""
    package = importlib.import_module("tests.operation_aware")
    assert package.__doc__ is not None
    assert "operation-aware" in package.__doc__


# ── Fixture-foundation accessibility ────────────────────────────────────────


def test_can_locate_the_pinned_snapshot_via_the_existing_helper() -> None:
    """The operation-aware test package can reach the pinned basis-schemas
    v0.2.0 snapshot through tests/helpers/basis_schemas_snapshot.py — no new
    fixture-loading behavior is added here."""
    contracts = list_operation_aware_contracts()
    scenarios = list_compatibility_scenarios()
    assert contracts, "Expected at least one vendored contract on disk."
    assert scenarios, "Expected at least one vendored compatibility scenario on disk."
    assert set(OPERATION_AWARE_CONTRACTS).issubset(set(contracts))
    assert set(COMPATIBILITY_SCENARIOS).issubset(set(scenarios))


def test_can_locate_one_known_contract() -> None:
    """Resolve exactly one known vendored contract's schema path — proof of
    accessibility, not a schema-shape assertion."""
    path = get_schema_path("operation-aware-decision-request")
    assert path.is_file()
    assert path.name == "operation-aware-decision-request.yaml"


def test_can_locate_one_known_compatibility_scenario() -> None:
    """Resolve exactly one known vendored scenario's request artifact —
    proof of accessibility, not a scenario-content assertion."""
    path = get_scenario_artifact("allow-basic", "request")
    assert path.is_file()
    assert path.name == "operation-aware-decision-request.yaml"


# ── Isolation from runtime code ─────────────────────────────────────────────


def test_no_operation_aware_production_package_exists_yet() -> None:
    """This scaffold must not anticipate a runtime package that doesn't
    exist. `src/basis_core/operation_aware` must not be importable — its
    absence is the point of this PR being test-infrastructure-only."""
    assert importlib.util.find_spec("basis_core.operation_aware") is None


def test_basis_core_public_import_does_not_expose_the_test_scaffold() -> None:
    """`import basis_core` must not pull in, or expose an attribute for,
    anything from this test package or the fixture-foundation helpers.
    Also confirms that merely running this test package (already imported,
    per `sys.modules`, by the time this assertion runs) never causes a
    `basis_core.operation_aware` submodule to load."""
    basis_core = importlib.import_module("basis_core")
    assert not hasattr(basis_core, "operation_aware")
    assert not hasattr(basis_core, "basis_schemas_snapshot")
    assert "tests.operation_aware" in sys.modules
    assert not any(mod.startswith("basis_core.operation_aware") for mod in sys.modules)


def test_basis_core_public_import_does_not_expose_fixture_helpers() -> None:
    """The fixture-foundation helper module's public names must not leak
    into the `basis_core` namespace via this new test package."""
    basis_core = importlib.import_module("basis_core")
    leaked = [
        name
        for name in ("get_schema_path", "get_scenario_artifact", "load_snapshot_manifest")
        if hasattr(basis_core, name)
    ]
    assert leaked == [], f"basis_core unexpectedly exposes fixture-helper name(s): {leaked}"
