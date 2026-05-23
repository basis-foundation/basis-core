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


def test_decisions_does_not_import_from_enforcement() -> None:
    """decisions/ defines the boundary contract; it must not import enforcement/."""
    imports = all_imports_in("decisions")
    violations = [(f, m) for f, m in imports if m.startswith("basis_core.enforcement")]
    assert violations == [], f"decisions/ imports from enforcement/: {violations}"
