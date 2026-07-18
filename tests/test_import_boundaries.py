"""
tests/test_import_boundaries.py — kernel boundary import assertions.

Verifies that basis-core remains a clean, isolated authorization kernel by
asserting that no source module imports from:
  - External framework packages (FastAPI, Flask, SQLAlchemy, requests, etc.)
  - OT protocol libraries (pymodbus, bacpypes, paho-mqtt, opcua, etc.)
  - Cloud provider SDKs (boto3, azure, google-cloud, etc.)
  - Kubernetes client libraries

Also asserts intra-package import rules:
  - domain/ imports nothing from any other basis_core subpackage
  - policy/ does not import from audit/, enforcement/, or adapters/
  - enforcement/ does not import from adapters/
  - audit/ does not import from enforcement/ or adapters/
  - policy/operation_aware/ (recursively-scanned, most recently extended by
    PR 27's aggregation.py) does not import from audit/, evaluation/,
    enforcement/, or adapters/
  - evaluation/ (including the recursively-scanned evaluation/operation_aware/
    subpackage, first created by PR 26) does not import from adapters/ or
    enforcement/

These tests use ast.parse() to inspect source files statically — they do not
execute any imports and do not depend on module loading order.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC_ROOT = Path(__file__).parent.parent / "src" / "basis_core"

# ── Helpers ────────────────────────────────────────────────────────────────────


def collect_imports(path: Path) -> list[str]:
    """Return all top-level imported module names found in a Python source file."""
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    imports: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.append(node.module)
    return imports


def all_imports_in(package: str) -> list[tuple[str, str]]:
    """Return (filename, module) tuples for all imports in a given package directory."""
    pkg_dir = SRC_ROOT / package
    results: list[tuple[str, str]] = []
    for py_file in sorted(pkg_dir.glob("*.py")):
        for module in collect_imports(py_file):
            results.append((py_file.name, module))
    return results


def all_kernel_imports() -> list[tuple[str, str]]:
    """Return (filename, module) tuples for every import across all kernel source files."""
    results: list[tuple[str, str]] = []
    for py_file in sorted(SRC_ROOT.rglob("*.py")):
        if "__pycache__" in str(py_file):
            continue
        for module in collect_imports(py_file):
            results.append((py_file.name, module))
    return results


# ── No external framework packages ────────────────────────────────────────────

# Prefixes that must never appear in kernel source imports.
FORBIDDEN_PREFIXES = (
    # Web frameworks
    "fastapi",
    "flask",
    "starlette",
    "django",
    "aiohttp",
    "tornado",
    "sanic",
    # HTTP clients
    "requests",
    "httpx",
    "urllib3",
    # ORMs / databases
    "sqlalchemy",
    "alembic",
    "tortoise",
    "databases",
    "asyncpg",
    "psycopg",
    "pymongo",
    "motor",
    "redis",
    # OT protocol libraries
    "pymodbus",
    "bacpypes",
    "bacpypes3",
    "pybacnet",
    "paho",
    "aiomqtt",
    "asyncio_mqtt",
    "opcua",
    "asyncua",
    # Cloud SDKs
    "boto3",
    "botocore",
    "azure",
    "google.cloud",
    "google.auth",
    # Kubernetes
    "kubernetes",
    # Keycloak / identity
    "keycloak",
    "python_keycloak",
    "authlib",
    "oauthlib",
    # Async task queues
    "celery",
    "dramatiq",
    "rq",
)


def test_kernel_does_not_import_web_frameworks() -> None:
    """No kernel source file may import a web framework."""
    all_imports = all_kernel_imports()
    violations = [
        (fname, mod)
        for fname, mod in all_imports
        if any(
            mod == prefix or mod.startswith(prefix + ".")
            for prefix in ("fastapi", "flask", "starlette", "django", "aiohttp", "tornado", "sanic")
        )
    ]
    assert violations == [], f"Kernel imports web framework(s): {violations}"


def test_kernel_does_not_import_http_clients() -> None:
    """No kernel source file may import an HTTP client library."""
    all_imports = all_kernel_imports()
    violations = [
        (fname, mod)
        for fname, mod in all_imports
        if any(
            mod == prefix or mod.startswith(prefix + ".")
            for prefix in ("requests", "httpx", "urllib3")
        )
    ]
    assert violations == [], f"Kernel imports HTTP client(s): {violations}"


def test_kernel_does_not_import_orm_or_database_libraries() -> None:
    """No kernel source file may import an ORM or database driver."""
    prefixes = (
        "sqlalchemy",
        "alembic",
        "tortoise",
        "databases",
        "asyncpg",
        "psycopg",
        "pymongo",
        "motor",
        "redis",
    )
    all_imports = all_kernel_imports()
    violations = [
        (fname, mod)
        for fname, mod in all_imports
        if any(mod == prefix or mod.startswith(prefix + ".") for prefix in prefixes)
    ]
    assert violations == [], f"Kernel imports ORM/database library: {violations}"


def test_kernel_does_not_import_ot_protocol_libraries() -> None:
    """No kernel source file may import an OT protocol library."""
    prefixes = (
        "pymodbus",
        "bacpypes",
        "bacpypes3",
        "pybacnet",
        "paho",
        "aiomqtt",
        "asyncio_mqtt",
        "opcua",
        "asyncua",
    )
    all_imports = all_kernel_imports()
    violations = [
        (fname, mod)
        for fname, mod in all_imports
        if any(mod == prefix or mod.startswith(prefix + ".") for prefix in prefixes)
    ]
    assert violations == [], f"Kernel imports OT protocol library: {violations}"


def test_kernel_does_not_import_cloud_sdks() -> None:
    """No kernel source file may import a cloud provider SDK."""
    prefixes = ("boto3", "botocore", "azure", "google.cloud", "google.auth", "kubernetes")
    all_imports = all_kernel_imports()
    violations = [
        (fname, mod)
        for fname, mod in all_imports
        if any(mod == prefix or mod.startswith(prefix + ".") for prefix in prefixes)
    ]
    assert violations == [], f"Kernel imports cloud SDK: {violations}"


# ── Intra-package import rules ────────────────────────────────────────────────


def test_domain_does_not_import_from_basis_core_subpackages() -> None:
    """
    domain/ is the dependency sink. It must not import from any other
    basis_core subpackage. All other packages may import from domain/.
    """
    imports = all_imports_in("domain")
    violations = [
        (fname, mod)
        for fname, mod in imports
        if mod.startswith("basis_core.") and not mod.startswith("basis_core.domain")
    ]
    assert violations == [], f"domain/ imports from basis_core subpackages: {violations}"


def test_policy_does_not_import_from_audit() -> None:
    """policy/ evaluates; it does not record. No audit imports allowed."""
    imports = all_imports_in("policy")
    violations = [(f, m) for f, m in imports if m.startswith("basis_core.audit")]
    assert violations == [], f"policy/ imports from audit/: {violations}"


def test_policy_does_not_import_from_enforcement() -> None:
    """policy/ must not import from enforcement/ — enforcement sits above policy."""
    imports = all_imports_in("policy")
    violations = [(f, m) for f, m in imports if m.startswith("basis_core.enforcement")]
    assert violations == [], f"policy/ imports from enforcement/: {violations}"


def test_policy_does_not_import_from_adapters() -> None:
    """policy/ reasons about domain types only, not adapter contracts."""
    imports = all_imports_in("policy")
    violations = [(f, m) for f, m in imports if m.startswith("basis_core.adapters")]
    assert violations == [], f"policy/ imports from adapters/: {violations}"


def test_enforcement_does_not_import_from_adapters() -> None:
    """
    enforcement/ orchestrates policy + audit. It must not import adapter
    contracts — adapters are normalized before the enforcement boundary.
    """
    imports = all_imports_in("enforcement")
    violations = [(f, m) for f, m in imports if m.startswith("basis_core.adapters")]
    assert violations == [], f"enforcement/ imports from adapters/: {violations}"


def test_audit_does_not_import_from_enforcement() -> None:
    """audit/ sits below enforcement/ in the dependency graph."""
    imports = all_imports_in("audit")
    violations = [(f, m) for f, m in imports if m.startswith("basis_core.enforcement")]
    assert violations == [], f"audit/ imports from enforcement/: {violations}"


def test_audit_does_not_import_from_adapters() -> None:
    """audit/ records decisions; it does not depend on adapter contracts."""
    imports = all_imports_in("audit")
    violations = [(f, m) for f, m in imports if m.startswith("basis_core.adapters")]
    assert violations == [], f"audit/ imports from adapters/: {violations}"


def test_audit_does_not_import_from_policy() -> None:
    """audit/ must not import from policy/ — the two sit at the same layer."""
    imports = all_imports_in("audit")
    violations = [(f, m) for f, m in imports if m.startswith("basis_core.policy")]
    assert violations == [], f"audit/ imports from policy/: {violations}"


def test_audit_operation_aware_does_not_import_from_policy_enforcement_or_adapters() -> None:
    """
    The top-level audit/ scanner above is non-recursive and does not cover
    the nested `audit/operation_aware/` package. This test protects that
    nested package specifically, scanning recursively so it also covers any
    future descendant modules added under it.
    """
    pkg_dir = SRC_ROOT / "audit" / "operation_aware"
    imports: list[tuple[str, str]] = []
    for py_file in sorted(pkg_dir.rglob("*.py")):
        for module in collect_imports(py_file):
            imports.append((py_file.name, module))
    violations = [
        (fname, mod)
        for fname, mod in imports
        if mod.startswith("basis_core.policy")
        or mod.startswith("basis_core.enforcement")
        or mod.startswith("basis_core.adapters")
    ]
    assert violations == [], f"audit/operation_aware/ imports a forbidden layer: {violations}"


def test_decisions_does_not_import_from_enforcement() -> None:
    """decisions/ defines the boundary contract; it must not import enforcement/."""
    imports = all_imports_in("decisions")
    violations = [(f, m) for f, m in imports if m.startswith("basis_core.enforcement")]
    assert violations == [], f"decisions/ imports from enforcement/: {violations}"


def test_policy_operation_aware_does_not_import_a_forbidden_layer() -> None:
    """
    The top-level `policy/` scanners above (`test_policy_does_not_import_
    from_audit`, `_from_enforcement`, `_from_adapters`) are non-recursive
    (`all_imports_in` uses `pkg_dir.glob("*.py")`) and do not cover the
    nested `policy/operation_aware/` package — first created by PR 12 and
    extended most recently by PR 27's `aggregation.py`
    (`docs/implementation/basis-core-v0.2-operation-aware-plan.md`,
    Milestone 9). `docs/import-boundaries.md` names this exact gap ("A
    matching recursive guard for `policy/operation_aware/` does not yet
    exist"); this test closes it, mirroring
    `test_audit_operation_aware_does_not_import_from_policy_enforcement_or_adapters`
    and `test_evaluation_operation_aware_does_not_import_from_adapters_or_enforcement`
    below. Per `docs/import-boundaries.md`, `policy/operation_aware/` uses
    the full `policy/` architecture ceiling (`domain/` + `decisions/`) but
    must never import `basis_core.audit`, `basis_core.evaluation`,
    `basis_core.enforcement`, or `basis_core.adapters` — all of which sit
    at or above `policy/` in the dependency graph.
    """
    pkg_dir = SRC_ROOT / "policy" / "operation_aware"
    imports: list[tuple[str, str]] = []
    for py_file in sorted(pkg_dir.rglob("*.py")):
        for module in collect_imports(py_file):
            imports.append((py_file.name, module))
    violations = [
        (fname, mod)
        for fname, mod in imports
        if mod.startswith("basis_core.audit")
        or mod.startswith("basis_core.evaluation")
        or mod.startswith("basis_core.enforcement")
        or mod.startswith("basis_core.adapters")
    ]
    assert violations == [], f"policy/operation_aware/ imports a forbidden layer: {violations}"


def test_evaluation_operation_aware_does_not_import_from_adapters_or_enforcement() -> None:
    """
    `evaluation/operation_aware/` (first created by PR 26 — see
    `docs/implementation/basis-core-v0.2-operation-aware-plan.md`, Milestone
    8) is the pure evaluation orchestration layer added by `basis-
    architecture` ADR-0006. Per `docs/import-boundaries.md`, it legally
    imports `basis_core.domain`, `basis_core.decisions`, `basis_core.policy`,
    and `basis_core.audit` (and its own siblings under `evaluation/`), but
    must never import `basis_core.adapters` or `basis_core.enforcement` —
    both sit above it in the dependency graph.

    This scans recursively (mirroring
    `test_audit_operation_aware_does_not_import_from_policy_enforcement_or_adapters`
    above) so it also covers any future descendant modules added under
    `evaluation/operation_aware/` (e.g. `engine.py`, `response_assembly.py`,
    per the roadmap's later, separately-scoped PRs) without requiring a new
    test each time.
    """
    pkg_dir = SRC_ROOT / "evaluation" / "operation_aware"
    imports: list[tuple[str, str]] = []
    for py_file in sorted(pkg_dir.rglob("*.py")):
        for module in collect_imports(py_file):
            imports.append((py_file.name, module))
    violations = [
        (fname, mod)
        for fname, mod in imports
        if mod.startswith("basis_core.adapters") or mod.startswith("basis_core.enforcement")
    ]
    assert violations == [], f"evaluation/operation_aware/ imports a forbidden layer: {violations}"


def test_evaluation_does_not_import_from_adapters_or_enforcement() -> None:
    """
    Top-level guard mirroring the package-level rule in
    `docs/import-boundaries.md`: no module directly under
    `src/basis_core/evaluation/` (non-recursive; the nested
    `operation_aware/` package has its own recursive guard above) may import
    `basis_core.adapters` or `basis_core.enforcement`.
    """
    imports = all_imports_in("evaluation")
    violations = [
        (fname, mod)
        for fname, mod in imports
        if mod.startswith("basis_core.adapters") or mod.startswith("basis_core.enforcement")
    ]
    assert violations == [], f"evaluation/ imports a forbidden layer: {violations}"
