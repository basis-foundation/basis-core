"""
tests/operation_aware/test_evidence_boundaries.py — import-boundary and
public-API-surface checks for `basis_core.domain.evidence` (Milestone 2, PR 6
of `docs/implementation/basis-core-v0.2-operation-aware-plan.md`).

Mirrors `test_vocabulary_boundaries.py` (PR 5) for the evidence-reference
module:

  1. The new module imports only the standard library plus `pydantic` (the
     one runtime dependency `basis-core` already declares) and its own
     sibling operation-aware vocabulary module — no YAML, no HTTP or
     cryptography library, no gateway/adapter/identity-provider library, and
     nothing from `tests/`.
  2. The new module is not yet re-exported from `basis_core.domain` or any
     other package `__init__.py` — per the roadmap's default position
     ("add internally now; stabilize and expose the public API later",
     Section 6).
  3. `docs/public-api.md` does not yet list `IdentityEvidenceReference`,
     `AdapterEvidenceReference`, or `EvidenceDigest` as part of the stable
     public API surface, matching (2).
  4. No existing v0.1.0 module imports the new evidence-reference module —
     the operation-aware surface is additive and inward-facing only.

These complement, and do not replace, the repository's existing generic
`tests/test_import_boundaries.py` (which already statically scans every
`domain/*.py` file, so this new module is automatically covered by its
`domain/` checks) and `tests/test_public_api.py` (the authoritative __all__
harness).
"""

from __future__ import annotations

import ast
from pathlib import Path

MODULE_PATH = Path(__file__).parent.parent.parent / "src" / "basis_core" / "domain" / "evidence.py"
SRC_ROOT = Path(__file__).parent.parent.parent / "src" / "basis_core"


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


class TestModuleImportBoundaries:
    def test_module_exists(self) -> None:
        assert MODULE_PATH.is_file(), f"Expected module not found: {MODULE_PATH}"

    def test_imports_are_stdlib_pydantic_or_sibling_vocabulary_module_only(self) -> None:
        imports = set(_collect_imports(MODULE_PATH))
        assert imports == {
            "__future__",
            "re",
            "pydantic",
            "basis_core.domain.operation_aware_vocabulary",
        }, (
            f"Unexpected import set for evidence.py: {imports}. This module must "
            "depend only on the standard library, pydantic, and its sibling "
            "operation-aware vocabulary module — no YAML, no HTTP or "
            "cryptography library, no protocol/adapter/identity-provider "
            "library, no test helpers."
        )

    def test_no_yaml_import(self) -> None:
        imports = _collect_imports(MODULE_PATH)
        assert not any(m == "yaml" or m.startswith("yaml.") for m in imports)

    def test_no_http_or_cryptography_import(self) -> None:
        forbidden_prefixes = (
            "requests",
            "httpx",
            "urllib",
            "cryptography",
            "jwt",
            "jose",
        )
        imports = _collect_imports(MODULE_PATH)
        violations = [
            m for m in imports if any(m == p or m.startswith(p + ".") for p in forbidden_prefixes)
        ]
        assert violations == []

    def test_no_test_helper_import(self) -> None:
        imports = _collect_imports(MODULE_PATH)
        assert not any(m == "tests" or m.startswith("tests.") for m in imports)

    def test_no_gateway_adapter_or_identity_provider_import(self) -> None:
        forbidden_prefixes = (
            "basis_gateway",
            "basis_adapters",
            "basis_identity",
            "keycloak",
            "python_keycloak",
            "authlib",
            "oauthlib",
        )
        imports = _collect_imports(MODULE_PATH)
        violations = [
            m for m in imports if any(m == p or m.startswith(p + ".") for p in forbidden_prefixes)
        ]
        assert violations == []

    def test_no_v01_module_imports_the_new_evidence_module(self) -> None:
        """No existing v0.1.0 `src/basis_core/` module may import the new
        evidence-reference module — the operation-aware surface is additive
        and inward-facing only; nothing in the existing kernel depends on
        it."""
        violations: list[tuple[str, str]] = []
        for py_file in sorted(SRC_ROOT.rglob("*.py")):
            if "__pycache__" in str(py_file) or py_file == MODULE_PATH:
                continue
            for module in _collect_imports(py_file):
                if module == "basis_core.domain.evidence":
                    violations.append((str(py_file), module))
        assert violations == [], (
            f"Existing v0.1.0 module(s) import the new evidence-reference module: {violations}"
        )


class TestPublicApiSurfaceUnchanged:
    def test_domain_init_does_not_export_the_new_types(self) -> None:
        init_path = SRC_ROOT / "domain" / "__init__.py"
        text = init_path.read_text(encoding="utf-8")
        assert "evidence" not in text
        assert "IdentityEvidenceReference" not in text
        assert "AdapterEvidenceReference" not in text
        assert "EvidenceDigest" not in text

    def test_no_basis_core_package_init_exports_the_new_types(self) -> None:
        for init_file in sorted(SRC_ROOT.rglob("__init__.py")):
            text = init_file.read_text(encoding="utf-8")
            assert "IdentityEvidenceReference" not in text
            assert "AdapterEvidenceReference" not in text
            assert "EvidenceDigest" not in text

    def test_public_api_doc_does_not_yet_list_the_new_types_as_stable(self) -> None:
        public_api_doc = Path(__file__).parent.parent.parent / "docs" / "public-api.md"
        text = public_api_doc.read_text(encoding="utf-8")
        # The roadmap plan itself may name these types in prose; the public
        # API inventory document must not yet list them under a stable
        # import-path table row (i.e. as part of "Stable public API").
        assert "| `IdentityEvidenceReference` |" not in text
        assert "| `AdapterEvidenceReference` |" not in text
        assert "| `EvidenceDigest` |" not in text


class TestNoGenericEvidenceReferenceTypeExposed:
    def test_module_does_not_define_a_generic_evidence_reference_base_class(self) -> None:
        """The roadmap explicitly says not to expose a generic
        `EvidenceReference` public type unless required. Confirm no such
        name is defined in the module."""
        source = MODULE_PATH.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(MODULE_PATH))
        class_names = {node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)}
        assert "EvidenceReference" not in class_names
