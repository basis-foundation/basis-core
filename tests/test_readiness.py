"""
tests/test_readiness.py — v0.1 release readiness smoke tests.

Three lightweight checks that confirm the package is correctly installed
and minimally functional as a distributable library:

  1. Version exposure  — basis_core.__version__ is present and matches pyproject.toml.
  2. Package import    — all six public subpackages are importable without error.
  3. Example execution — the basic_evaluation example runs end-to-end without raising.

These tests are intentionally minimal. They do not retest contracts already
covered by test_public_api.py, test_contract_snapshots.py, or test_evaluation_semantics.py.
Their purpose is to catch packaging regressions (missing files, broken __init__ imports,
example bit-rot) that unit tests would not catch.
"""

from __future__ import annotations

import importlib
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent


# ── 1. Version exposure ────────────────────────────────────────────────────────


class TestVersionExposure:
    """basis_core must expose a __version__ string matching pyproject.toml."""

    def test_version_attribute_exists(self) -> None:
        import basis_core

        assert hasattr(basis_core, "__version__"), (
            "basis_core.__version__ is missing. "
            "Add __version__ = '...' to src/basis_core/__init__.py."
        )

    def test_version_is_string(self) -> None:
        import basis_core

        assert isinstance(basis_core.__version__, str)

    def test_version_is_non_empty(self) -> None:
        import basis_core

        assert basis_core.__version__.strip(), "basis_core.__version__ must not be empty."

    def test_version_matches_pyproject(self) -> None:
        """The __version__ string must match the version declared in pyproject.toml."""
        import basis_core

        pyproject = REPO_ROOT / "pyproject.toml"
        content = pyproject.read_text(encoding="utf-8")
        # Extract the first `version = "..."` line in the [project] table.
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("version") and "=" in stripped:
                declared = stripped.split("=", 1)[1].strip().strip('"').strip("'")
                assert basis_core.__version__ == declared, (
                    f"basis_core.__version__ ({basis_core.__version__!r}) "
                    f"does not match pyproject.toml version ({declared!r})."
                )
                return
        pytest.fail("Could not find version declaration in pyproject.toml.")


# ── 2. Package import smoke test ──────────────────────────────────────────────


PUBLIC_PACKAGES = [
    "basis_core",
    "basis_core.domain",
    "basis_core.decisions",
    "basis_core.policy",
    "basis_core.audit",
    "basis_core.enforcement",
    "basis_core.adapters",
]


@pytest.mark.parametrize("package", PUBLIC_PACKAGES)
def test_public_package_importable(package: str) -> None:
    """Every public package must be importable without error."""
    mod = importlib.import_module(package)
    assert mod is not None, f"importlib.import_module({package!r}) returned None."


# ── 3. Example execution smoke test ──────────────────────────────────────────


class TestExampleExecution:
    """The basic_evaluation example must run end-to-end without raising."""

    def test_basic_evaluation_runs(self) -> None:
        """
        Run examples/basic_evaluation.py as a subprocess so that it exercises
        the full import and execution path in a clean interpreter state.
        """
        example = REPO_ROOT / "examples" / "basic_evaluation.py"
        assert example.is_file(), f"Example file not found: {example}"

        result = subprocess.run(
            [sys.executable, str(example)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, (
            f"examples/basic_evaluation.py exited with code {result.returncode}.\n"
            f"stdout: {result.stdout}\n"
            f"stderr: {result.stderr}"
        )

    def test_basic_evaluation_produces_output(self) -> None:
        """The example must write at least one ALLOW or DENY verdict to stdout."""
        example = REPO_ROOT / "examples" / "basic_evaluation.py"
        result = subprocess.run(
            [sys.executable, str(example)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = result.stdout + result.stderr
        assert "ALLOW" in output or "DENY" in output, (
            "examples/basic_evaluation.py produced no ALLOW/DENY output. "
            f"stdout: {result.stdout!r}  stderr: {result.stderr!r}"
        )
