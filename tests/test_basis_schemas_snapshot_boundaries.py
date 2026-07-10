"""
tests/test_basis_schemas_snapshot_boundaries.py — scope-boundary tests for
the operation-aware schema/fixture snapshot foundation.

Proves the two hard boundaries this PR must not cross:

  1. The public `basis_core` API surface (`docs/public-api.md`) is unchanged
     — this PR adds test fixtures and test helpers only, no new exports.
  2. No `src/basis_core/` module imports anything from `tests/` — the
     vendored snapshot and its helpers are test/development input only,
     never a runtime dependency.

Cross-references
─────────────────
docs/public-api.md            — the authoritative public API inventory.
tests/test_public_api.py      — the existing, unmodified public API harness.
tests/test_import_boundaries.py — the existing kernel import-boundary harness.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC_ROOT = Path(__file__).parent.parent / "src" / "basis_core"


def _collect_imports(path: Path) -> list[str]:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    imports: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.append(node.module)
    return imports


class TestRuntimePackageDoesNotImportTestHelpers:
    def test_no_kernel_source_file_imports_from_tests(self) -> None:
        violations: list[tuple[str, str]] = []
        for py_file in sorted(SRC_ROOT.rglob("*.py")):
            if "__pycache__" in str(py_file):
                continue
            for module in _collect_imports(py_file):
                if module == "tests" or module.startswith("tests."):
                    violations.append((str(py_file), module))
        assert violations == [], (
            f"Kernel source file(s) import from tests/: {violations}. "
            "The vendored basis-schemas snapshot and its test helpers are "
            "test/development input only, never a runtime dependency."
        )

    def test_no_kernel_source_file_imports_basis_schemas(self) -> None:
        """basis-schemas is never a runtime dependency of basis-core (see
        docs/implementation/basis-core-v0.2-operation-aware-plan.md, Section
        4). This is a stronger, more direct check than the tests/ check
        above: even an indirect or aliased import of the package name itself
        must not appear anywhere under src/."""
        violations: list[tuple[str, str]] = []
        for py_file in sorted(SRC_ROOT.rglob("*.py")):
            if "__pycache__" in str(py_file):
                continue
            for module in _collect_imports(py_file):
                if module == "basis_schemas" or module.startswith("basis_schemas."):
                    violations.append((str(py_file), module))
        assert violations == [], f"Kernel source file(s) import basis_schemas: {violations}"


class TestPublicApiUnchanged:
    def test_public_api_doc_does_not_reference_the_vendored_snapshot(self) -> None:
        """docs/public-api.md is the authoritative public inventory. This PR
        must not add an entry for the snapshot, the refresh script, or the
        test helper module — none of them are public API."""
        public_api_doc = Path(__file__).parent.parent / "docs" / "public-api.md"
        text = public_api_doc.read_text(encoding="utf-8")
        forbidden_mentions = (
            "basis_schemas_snapshot",
            "update_basis_schemas_snapshot",
            "tests/fixtures/basis-schemas",
        )
        for mention in forbidden_mentions:
            assert mention not in text, (
                f"docs/public-api.md unexpectedly mentions {mention!r} — the "
                "operation-aware snapshot must not become part of the public API."
            )

    def test_no_basis_core_package_init_exports_snapshot_helpers(self) -> None:
        for init_file in sorted((SRC_ROOT).rglob("__init__.py")):
            text = init_file.read_text(encoding="utf-8")
            assert "basis_schemas_snapshot" not in text
            assert "update_basis_schemas_snapshot" not in text

    def test_scripts_directory_is_not_part_of_the_installed_wheel_packages(self) -> None:
        """pyproject.toml's [tool.hatch.build.targets.wheel] must continue to
        package only src/basis_core — scripts/ (the new refresh tool) must
        not be added to the built package."""
        pyproject_path = Path(__file__).parent.parent / "pyproject.toml"
        text = pyproject_path.read_text(encoding="utf-8")
        assert 'packages = ["src/basis_core"]' in text
