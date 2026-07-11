"""
tests/operation_aware/test_context_boundaries.py — import-boundary and
public-API-surface checks for `basis_core.domain.operation_aware` (Milestone
2, PR 7 of `docs/implementation/basis-core-v0.2-operation-aware-plan.md`).

Mirrors `test_vocabulary_boundaries.py` (PR 5) and `test_evidence_boundaries.py`
(PR 6) for the context-object module:

  1. The new module imports only the standard library plus `pydantic` (the
     one runtime dependency `basis-core` already declares) — no sibling
     operation-aware module (this PR's six context objects do not nest any
     PR 5 vocabulary type or PR 6 evidence-reference type; the published
     contract keeps evidence references as separate, sibling fields on the
     future request, not nested inside these six shapes), no YAML, no HTTP
     or cryptography library, no gateway/adapter/identity-provider library,
     and nothing from `tests/`.
  2. The new module is not yet re-exported from `basis_core.domain` or any
     other package `__init__.py` — per the roadmap's default position
     ("add internally now; stabilize and expose the public API later",
     Section 6).
  3. `docs/public-api.md` does not yet list any of this module's six context
     types as part of the stable public API surface, matching (2).
  4. No existing v0.1.0 module imports the new context-object module — the
     operation-aware surface is additive and inward-facing only.

No allowlist change was required in `test_vocabulary_boundaries.py` or
`test_evidence_boundaries.py`: unlike PR 6 (which legitimately depends on
PR 5's `RedactionClassification`), this PR's context objects have no import
dependency on either sibling module, so neither existing boundary test's
"no module imports X" allowlist needed updating.

These complement, and do not replace, the repository's existing generic
`tests/test_import_boundaries.py` (which already statically scans every
`domain/*.py` file, so this new module is automatically covered by its
`domain/` checks) and `tests/test_public_api.py` (the authoritative __all__
harness).
"""

from __future__ import annotations

import ast
from pathlib import Path

MODULE_PATH = (
    Path(__file__).parent.parent.parent / "src" / "basis_core" / "domain" / "operation_aware.py"
)
SRC_ROOT = Path(__file__).parent.parent.parent / "src" / "basis_core"


def _is_operation_aware_sibling_module(path: Path) -> bool:
    """True for any `src/basis_core/` module that is itself part of the
    operation-aware surface (file stem or an ancestor directory name
    contains ``"operation_aware"``) — e.g. `domain/operation_aware.py`,
    `domain/operation_aware_vocabulary.py`, `decisions/operation_aware.py`
    (PR 8), and any future `policy/operation_aware/*.py` or
    `audit/operation_aware/*.py` module. These modules composing one
    another along the roadmap's declared import graph
    (`docs/implementation/basis-core-v0.2-operation-aware-plan.md` Section
    5) is expected and is not a "v0.1.0 module depends on operation-aware
    code" violation — only a genuine v0.1.0 (non-operation-aware) importer
    is. Added in PR 8, when `decisions/operation_aware.py` became the first
    sibling module to legitimately import this one."""
    return (
        path.stem == "operation_aware"
        or path.stem.startswith("operation_aware_")
        or "operation_aware" in path.parts
    )


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

    def test_imports_are_stdlib_or_pydantic_only(self) -> None:
        imports = set(_collect_imports(MODULE_PATH))
        assert imports == {"__future__", "math", "re", "pydantic"}, (
            f"Unexpected import set for operation_aware.py: {imports}. This module must "
            "depend only on the standard library and pydantic — no sibling "
            "operation-aware module, no YAML, no HTTP or cryptography library, no "
            "protocol/adapter/identity-provider library, no test helpers."
        )

    def test_no_sibling_operation_aware_module_import(self) -> None:
        """Unlike evidence.py (PR 6), this PR's context objects do not nest
        any PR 5 vocabulary type or PR 6 evidence-reference type — the
        published contract keeps evidence references as separate, sibling
        request fields, not nested inside these six shapes."""
        imports = _collect_imports(MODULE_PATH)
        assert not any(
            m
            in {
                "basis_core.domain.operation_aware_vocabulary",
                "basis_core.domain.evidence",
            }
            for m in imports
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

    def test_no_v01_module_imports_the_new_context_module(self) -> None:
        """No existing v0.1.0 `src/basis_core/` module may import the new
        context-object module — the operation-aware surface is additive
        and inward-facing only; nothing in the existing v0.1.0 kernel
        depends on it. A sibling operation-aware module (e.g.
        `decisions/operation_aware.py`, PR 8) importing this one is
        expected and excluded — see `_is_operation_aware_sibling_module`."""
        violations: list[tuple[str, str]] = []
        for py_file in sorted(SRC_ROOT.rglob("*.py")):
            if (
                "__pycache__" in str(py_file)
                or py_file == MODULE_PATH
                or _is_operation_aware_sibling_module(py_file)
            ):
                continue
            for module in _collect_imports(py_file):
                if module == "basis_core.domain.operation_aware":
                    violations.append((str(py_file), module))
        assert violations == [], (
            f"Existing v0.1.0 module(s) import the new context-object module: {violations}"
        )


class TestPublicApiSurfaceUnchanged:
    _NEW_TYPE_NAMES = (
        "OperationAwareLocation",
        "OperationAwareDevice",
        "OperationAwareProtocolContext",
        "OperationAwareSafetyContext",
        "OperationAwareEnvironmentContext",
        "OperationAwareRiskContext",
    )

    def test_domain_init_does_not_export_the_new_types(self) -> None:
        init_path = SRC_ROOT / "domain" / "__init__.py"
        text = init_path.read_text(encoding="utf-8")
        assert "operation_aware " not in text
        assert "operation_aware\n" not in text
        assert "from basis_core.domain.operation_aware " not in text
        for name in self._NEW_TYPE_NAMES:
            assert name not in text

    def test_no_basis_core_package_init_exports_the_new_types(self) -> None:
        for init_file in sorted(SRC_ROOT.rglob("__init__.py")):
            text = init_file.read_text(encoding="utf-8")
            for name in self._NEW_TYPE_NAMES:
                assert name not in text

    def test_public_api_doc_does_not_yet_list_the_new_types_as_stable(self) -> None:
        public_api_doc = Path(__file__).parent.parent.parent / "docs" / "public-api.md"
        text = public_api_doc.read_text(encoding="utf-8")
        for name in self._NEW_TYPE_NAMES:
            assert f"| `{name}` |" not in text


class TestNoSensitiveFieldsExposed:
    """The context objects must not admit raw security/protocol artifacts —
    they carry bounded normalized values only. `extra="forbid"` (checked
    directly in test_context_objects.py) is the runtime enforcement; this
    confirms none of the six models *declares* such a field in source."""

    _PROHIBITED_FIELD_NAMES = (
        "access_token",
        "refresh_token",
        "id_token",
        "authorization_header",
        "password",
        "client_secret",
        "private_key",
        "raw_claims",
        "raw_token",
        "raw_protocol_payload",
        "raw_packet",
        "credential",
    )

    def test_no_model_declares_a_prohibited_field_name(self) -> None:
        from basis_core.domain.operation_aware import (
            OperationAwareDevice,
            OperationAwareEnvironmentContext,
            OperationAwareLocation,
            OperationAwareProtocolContext,
            OperationAwareRiskContext,
            OperationAwareSafetyContext,
        )

        models = [
            OperationAwareLocation,
            OperationAwareDevice,
            OperationAwareProtocolContext,
            OperationAwareSafetyContext,
            OperationAwareEnvironmentContext,
            OperationAwareRiskContext,
        ]
        for model in models:
            declared_fields = set(model.model_fields)
            assert declared_fields.isdisjoint(self._PROHIBITED_FIELD_NAMES), (
                f"{model.__name__} declares a prohibited field."
            )
