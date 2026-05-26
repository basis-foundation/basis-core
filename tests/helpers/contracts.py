"""
tests.helpers.contracts — utilities for contract fixture loading and comparison.

These helpers support tests/test_contract_snapshots.py and
tests/test_backward_compatibility.py. They provide a single, consistent way to:

  - Locate and load fixture files from tests/fixtures/contracts/
  - Normalize model serializations for deterministic comparison
  - Compare a live model instance against a stored fixture
  - Load raw JSON fixtures for schema-validation and round-trip tests

Normalization
─────────────
JSON objects are compared after JSON-round-trip serialization with sorted keys.
This makes comparison insensitive to Python dict insertion order while remaining
sensitive to all field names, values, and nesting. It does NOT normalize field
values (timestamps, UUIDs): fixtures must carry exactly the values that the
models produce.

Usage
─────
    from tests.helpers.contracts import load_fixture, assert_matches_fixture

    fixture = load_fixture("decision_request.allow")
    assert_matches_fixture(model_instance, "decision_request.allow")
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel

# Absolute path to the contracts fixture directory.
FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "contracts"


def load_fixture(name: str) -> dict[str, Any]:
    """
    Load a contract fixture by name (without the .json extension).

    Args:
        name: Fixture stem, e.g. "decision_request.allow" or "audit_event.deny".

    Returns:
        The parsed fixture as a dict.

    Raises:
        FileNotFoundError: If the fixture file does not exist.
        ValueError: If the fixture does not parse as a JSON object.
    """
    path = FIXTURES_DIR / f"{name}.json"
    if not path.exists():
        raise FileNotFoundError(
            f"Contract fixture not found: {path}. "
            "Create it in tests/fixtures/contracts/ to establish the contract."
        )
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(
            f"Contract fixture {name!r} must be a JSON object (dict), got {type(raw).__name__}."
        )
    return raw  # type: ignore[return-value]


def normalize(data: dict[str, Any] | str) -> str:
    """
    Normalize a dict or JSON string to a canonical, sorted-key JSON string.

    Used to compare model output against stored fixtures regardless of key
    insertion order.
    """
    if isinstance(data, str):
        data = json.loads(data)
    return json.dumps(data, sort_keys=True, ensure_ascii=False)


def model_to_normalized(model: BaseModel) -> str:
    """
    Serialize a Pydantic model to a canonical sorted-key JSON string.

    Uses model_dump_json to preserve Pydantic's datetime serialization
    (which emits 'Z' for UTC rather than '+00:00'), then re-normalizes with
    sorted keys.
    """
    raw = json.loads(model.model_dump_json())
    return normalize(raw)


def assert_matches_fixture(
    model: BaseModel,
    fixture_name: str,
    *,
    msg: str | None = None,
) -> None:
    """
    Assert that a model instance serializes identically to a stored fixture.

    Compares the normalized JSON of the model against the normalized JSON of
    the fixture. Fails with a descriptive diff if they differ.

    Args:
        model:        The Pydantic model instance to check.
        fixture_name: Fixture stem (e.g. "decision_request.allow").
        msg:          Optional extra message appended to assertion failure output.
    """
    fixture = load_fixture(fixture_name)
    actual = model_to_normalized(model)
    expected = normalize(fixture)

    if actual != expected:
        actual_dict = json.loads(actual)
        expected_dict = json.loads(expected)
        all_keys = sorted(set(actual_dict) | set(expected_dict))
        diffs: list[str] = []
        for k in all_keys:
            a_val = actual_dict.get(k, "<missing>")
            e_val = expected_dict.get(k, "<missing>")
            if a_val != e_val:
                diffs.append(f"  {k!r}: actual={a_val!r}, expected={e_val!r}")
        _fallback = "  (structural difference — check nested objects)"
        diff_lines = "\n".join(diffs) if diffs else _fallback
        extra = f"\n{msg}" if msg else ""
        raise AssertionError(
            f"Model does not match contract fixture {fixture_name!r}.\n"
            f"Field differences:\n{diff_lines}{extra}"
        )


def fixture_names() -> list[str]:
    """
    Return a sorted list of all fixture stems in tests/fixtures/contracts/.

    Used by tests that verify the complete fixture inventory.
    """
    return sorted(p.stem for p in FIXTURES_DIR.glob("*.json"))
