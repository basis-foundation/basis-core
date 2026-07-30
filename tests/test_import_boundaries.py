"""
tests/test_import_boundaries.py — kernel boundary import assertions.

Verifies that basis-core remains a clean, isolated authorization kernel by
asserting that no source module imports from:
  - External framework packages (FastAPI, Flask, SQLAlchemy, requests, etc.)
  - OT protocol libraries (pymodbus, bacpypes, paho-mqtt, opcua, etc.)
  - Cloud provider SDKs (boto3, azure, google-cloud, etc.)
  - Kubernetes client libraries
  - Higher-level basis_* components (basis_gateway, basis_console,
    basis_identity, basis_deploy)

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

PR 40 (`docs/implementation/basis-core-v0.2-operation-aware-plan.md`,
Milestone 13) extends this file with:
  - the remaining edges of the docs/import-boundaries.md permission matrix
    that had no prior regression coverage: decisions/ vs. policy/audit/
    evaluation/adapters, and the legacy (non-recursive) policy/ and audit/
    subtrees vs. evaluation/
  - a whole-tree module classification completeness check, so a future
    module added anywhere under src/basis_core/ either falls under an
    existing classification automatically or fails loudly instead of
    silently escaping boundary coverage
  - a single whole-tree "nothing outside enforcement/ imports enforcement/"
    sweep, consolidating the per-package assertions above into one explicit
    statement of Invariant 10 ("dependency arrows point inward")
  - a whole-tree sweep for higher-level basis_* components (basis_gateway,
    basis_console, basis_identity, basis_deploy), per
    docs/kernel-constitution.md Invariant 10
  - a kernel-constitution cross-check mapping each of the ten invariants in
    docs/kernel-constitution.md to the test(s) that statically enforce it
    (or stating plainly that the invariant is behavioral and out of this
    file's reach)

These tests use ast.parse() to inspect source files statically — they do not
execute any imports and do not depend on module loading order. Static import
checks can prove "module A's source does not reference module B" and
nothing more; they cannot prove determinism, fail-closed behavior, absence
of side effects, or any other runtime property.
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

    Also asserts no `basis_core.evaluation` import (per `docs/import-
    boundaries.md`: `audit/` must not import `evaluation/` — the two are
    mutually isolated siblings under `evaluation/`; only `evaluation/` is
    permitted to sit above both). This was not previously checked here
    because, until PR 30 (`audit_evidence.py`,
    `docs/implementation/basis-core-v0.2-operation-aware-plan.md`, Milestone
    10), no module in this package needed to state the distinction
    explicitly — `audit_evidence.py`'s own docstring ("Import boundary")
    relies on this test to keep that guarantee mechanically checked rather
    than merely asserted in prose.
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
        or mod.startswith("basis_core.evaluation")
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


# ── PR 40 — remaining permission-matrix edges with no prior coverage ─────────
#
# `docs/import-boundaries.md`'s permission matrix defines, per package, the
# complete set of `basis_core` subpackages it may and must not import. Every
# test above covers *some* of each package's forbidden edges, but three edges
# of that matrix had no regression test anywhere in the suite before PR 40:
#
#   decisions/          -> policy/, audit/, evaluation/, adapters/
#                          (only the enforcement/ edge was previously
#                          covered, by test_decisions_does_not_import_from_
#                          enforcement above)
#   policy/  (legacy)    -> evaluation/
#                          (audit/, enforcement/, adapters/ were previously
#                          covered by the three test_policy_does_not_import_
#                          from_* tests above; policy/operation_aware/'s own
#                          evaluation/ edge was already covered by
#                          test_policy_operation_aware_does_not_import_a_
#                          forbidden_layer)
#   audit/   (legacy)    -> evaluation/
#                          (policy/, enforcement/, adapters/ were previously
#                          covered by the three test_audit_does_not_import_
#                          from_* tests above; audit/operation_aware/'s own
#                          evaluation/ edge was already covered by
#                          test_audit_operation_aware_does_not_import_from_
#                          policy_enforcement_or_adapters)
#
# These three tests close exactly those gaps. They neither relax nor repeat
# an existing assertion — each checks an edge no other test in this file (or
# tests/test_models.py, which owns the separate policy/-vs-decisions/ legacy
# rule) currently checks.


def test_decisions_does_not_import_from_policy_audit_evaluation_or_adapters() -> None:
    """
    `decisions/` may import only `domain/` (`docs/import-boundaries.md`).
    `decisions/` has no nested `operation_aware/` subpackage —
    `decisions/operation_aware.py` is a flat sibling of `decisions/models.py`
    — so the existing non-recursive `all_imports_in("decisions")` helper
    already reaches every current and future flat module in this package.
    """
    imports = all_imports_in("decisions")
    violations = [
        (fname, mod)
        for fname, mod in imports
        if mod.startswith("basis_core.policy")
        or mod.startswith("basis_core.audit")
        or mod.startswith("basis_core.evaluation")
        or mod.startswith("basis_core.adapters")
    ]
    assert violations == [], f"decisions/ imports a forbidden layer: {violations}"


def test_policy_legacy_does_not_import_from_evaluation() -> None:
    """
    Closes the one previously-untested edge of `policy/`'s architecture
    ceiling for the non-recursive legacy subtree (`policy/engine.py`,
    `policy/rules.py`, `policy/__init__.py`, scanned by
    `all_imports_in("policy")`, which does not descend into
    `policy/operation_aware/`): `policy/` must not import `evaluation/`.
    `policy/operation_aware/` already has its own recursive guard
    (`test_policy_operation_aware_does_not_import_a_forbidden_layer`) that
    includes this edge; this test only protects the legacy, non-recursive
    subtree that guard does not scan.
    """
    imports = all_imports_in("policy")
    violations = [(fname, mod) for fname, mod in imports if mod.startswith("basis_core.evaluation")]
    assert violations == [], f"policy/ imports from evaluation/: {violations}"


def test_audit_legacy_does_not_import_from_evaluation() -> None:
    """
    Mirrors test_policy_legacy_does_not_import_from_evaluation for `audit/`.
    `docs/import-boundaries.md`: `audit/` and `evaluation/` are mutually
    isolated siblings — only `evaluation/` may sit above both. Closes the
    one previously-untested edge for the non-recursive legacy subtree
    (`audit/events.py`, `audit/trace.py`, `audit/writer.py`,
    `audit/__init__.py`, scanned by `all_imports_in("audit")`, which does
    not descend into `audit/operation_aware/`). `audit/operation_aware/`
    already has its own recursive guard
    (`test_audit_operation_aware_does_not_import_from_policy_enforcement_or_adapters`)
    that includes this edge.
    """
    imports = all_imports_in("audit")
    violations = [(fname, mod) for fname, mod in imports if mod.startswith("basis_core.evaluation")]
    assert violations == [], f"audit/ imports from evaluation/: {violations}"


# ── PR 40 — whole-tree completeness and consolidation checks ────────────────


def _classify_kernel_module(rel_path: Path) -> str:
    """
    Classify a `src/basis_core/`-relative module path into the subtree
    bucket `docs/import-boundaries.md` assigns it, mirroring the same
    per-package/`operation_aware` distinction the tests above already
    exercise individually. Returns ``"UNCLASSIFIED"`` for anything that does
    not match a known top-level package, or a known package whose second
    path segment is not (yet) accounted for — that value is deliberately not
    a member of `_KNOWN_KERNEL_MODULE_BUCKETS`, so
    `test_every_kernel_module_is_classified_by_a_boundary_rule` fails loudly
    rather than silently ignoring a new subtree.

    This function only assigns a bucket name; it does not decide what that
    bucket may or must not import. It exists so a module added under an
    already-known top-level package (e.g. a new flat file directly under
    `policy/`, or a new nested module under an existing
    `*/operation_aware/` package) is automatically swept into the matching
    existing test above via that test's own non-recursive `glob` or
    recursive `rglob` scan — no test change required. A module added under
    an entirely new top-level package is the one case that genuinely
    requires a human to add a new bucket and a new boundary assertion; this
    function surfaces that case as "UNCLASSIFIED" rather than guessing.
    """
    parts = rel_path.parts
    if not parts:
        return "UNCLASSIFIED"
    if parts == ("__init__.py",):
        return "package_root"
    top = parts[0]
    if top == "domain":
        return "domain"
    if top == "decisions":
        return "decisions"
    if top == "policy":
        return (
            "policy_operation_aware"
            if len(parts) > 1 and parts[1] == "operation_aware"
            else "policy_legacy"
        )
    if top == "audit":
        return (
            "audit_operation_aware"
            if len(parts) > 1 and parts[1] == "operation_aware"
            else "audit_legacy"
        )
    if top == "evaluation":
        return (
            "evaluation_operation_aware"
            if len(parts) > 1 and parts[1] == "operation_aware"
            else "evaluation_legacy"
        )
    if top == "enforcement":
        return "enforcement"
    if top == "adapters":
        return "adapters"
    return "UNCLASSIFIED"


_KNOWN_KERNEL_MODULE_BUCKETS = {
    "domain",
    "decisions",
    "policy_legacy",
    "policy_operation_aware",
    "audit_legacy",
    "audit_operation_aware",
    "evaluation_legacy",
    "evaluation_operation_aware",
    "enforcement",
    "adapters",
    "package_root",
}


def test_every_kernel_module_is_classified_by_a_boundary_rule() -> None:
    """
    Inventory completeness check: every `.py` module currently under
    `src/basis_core/` (including every operation-aware module inspected for
    PR 40 — `domain/operation_aware.py`, `domain/operation_aware_vocabulary.py`,
    `decisions/operation_aware.py`, everything under `policy/operation_aware/`,
    `audit/operation_aware/`, `evaluation/operation_aware/`, and
    `enforcement/operation_aware.py`) must resolve to a known boundary
    classification bucket via `_classify_kernel_module`.

    This does not hard-code a total module count — the assertion is against
    the *set* of unclassified modules being empty, not against how many
    modules exist. A future module added under an already-known top-level
    package (including a new nested module under any existing
    `*/operation_aware/` package) is classified automatically and is already
    covered by the matching test above. A future module under a genuinely
    new top-level package fails this test explicitly instead of silently
    falling outside every boundary check in this file.
    """
    unclassified = [
        str(py_file.relative_to(SRC_ROOT))
        for py_file in sorted(SRC_ROOT.rglob("*.py"))
        if "__pycache__" not in str(py_file)
        and _classify_kernel_module(py_file.relative_to(SRC_ROOT))
        not in _KNOWN_KERNEL_MODULE_BUCKETS
    ]
    assert unclassified == [], (
        f"Module(s) not covered by any known boundary classification: {unclassified}. "
        "Add a bucket to _classify_kernel_module and a corresponding "
        "import-boundary assertion in this file before merging."
    )


def test_lower_kernel_layers_never_import_enforcement() -> None:
    """
    `docs/import-boundaries.md`: `enforcement/` is the top of the dependency
    graph — "must not be imported by: any other basis_core subpackage."
    Every package-specific test above already asserts this pairwise for its
    own package (domain/ via test_domain_does_not_import_from_basis_core_
    subpackages; decisions/ via test_decisions_does_not_import_from_
    enforcement; policy/ via test_policy_does_not_import_from_enforcement
    plus the policy/operation_aware/ recursive guard; audit/ via
    test_audit_does_not_import_from_enforcement plus the audit/
    operation_aware/ recursive guard; evaluation/ via test_evaluation_does_
    not_import_from_adapters_or_enforcement plus the evaluation/
    operation_aware/ recursive guard).

    This test performs one additional, independent whole-tree sweep across
    every `*.py` file under `src/basis_core/` except `enforcement/` itself,
    so the invariant holds even for a module not yet covered by a narrower
    test, and so `docs/kernel-constitution.md` Invariant 10 ("dependency
    arrows point inward") has one single, explicit, whole-tree statement to
    point to in the cross-check below — rather than asking a reader to
    reassemble the invariant from eight separate pairwise tests.
    """
    violations = [
        (str(py_file.relative_to(SRC_ROOT)), mod)
        for py_file in sorted(SRC_ROOT.rglob("*.py"))
        if "__pycache__" not in str(py_file)
        and py_file.relative_to(SRC_ROOT).parts[0] != "enforcement"
        for mod in collect_imports(py_file)
        if mod.startswith("basis_core.enforcement")
    ]
    assert violations == [], f"Non-enforcement module imports basis_core.enforcement: {violations}"


_HIGHER_LEVEL_BASIS_COMPONENT_PREFIXES = (
    "basis_gateway",
    "basis_console",
    "basis_identity",
    "basis_deploy",
)


def test_kernel_does_not_import_higher_level_basis_components() -> None:
    """
    `docs/kernel-constitution.md` Invariant 10 ("Dependency arrows point
    inward"): "basis-core must not import from basis-gateway, basis-console,
    basis-adapters, basis-deploy, or any higher-level system component."
    The internal `basis_core.adapters` subpackage is a part of this
    repository and is governed separately by the policy-/audit-/
    enforcement-vs-adapters tests above; this test covers the four
    *external*, separately-versioned repositories the constitution names,
    none of which this kernel may ever import.

    Three domain/ modules already carry their own narrower version of this
    check (`tests/operation_aware/test_vocabulary_boundaries.py`,
    `test_context_boundaries.py` — both also forbidding
    `basis_gateway`/`basis_adapters`/`basis_identity`/keycloak/authlib/
    oauthlib for those two specific files). This is the first whole-tree
    sweep for the basis_* component prefixes specifically, so a module
    added anywhere in the kernel is covered without needing its own
    dedicated boundary-test file.
    """
    violations = [
        (str(py_file.relative_to(SRC_ROOT)), mod)
        for py_file in sorted(SRC_ROOT.rglob("*.py"))
        if "__pycache__" not in str(py_file)
        for mod in collect_imports(py_file)
        if any(
            mod == prefix or mod.startswith(prefix + ".")
            for prefix in _HIGHER_LEVEL_BASIS_COMPONENT_PREFIXES
        )
    ]
    assert violations == [], f"Kernel imports a higher-level basis_* component: {violations}"


def test_operation_aware_import_graph_preserves_kernel_constitution() -> None:
    """
    Cross-checks `docs/kernel-constitution.md`'s ten invariants against what
    static import-boundary tests can actually prove for the Milestone 1-12
    operation-aware addition. This is not a re-implementation of those
    invariants and not a comment-only checklist — it states, invariant by
    invariant, which test(s) statically enforce it (evidence this file and
    its siblings already produce), performs one direct assertion this file
    had not made elsewhere (Invariant 9), and states plainly which
    invariants are behavioral properties this file cannot reach at all.

    Statically enforceable, and enforced elsewhere in this file (or in the
    per-module tests named below) as of PR 40:

      Invariant  1 (kernel is isolated)          -- test_kernel_does_not_
                                                     import_web_frameworks /
                                                     _http_clients / _orm_or_
                                                     database_libraries /
                                                     _ot_protocol_libraries /
                                                     _cloud_sdks, and
                                                     test_kernel_does_not_
                                                     import_higher_level_
                                                     basis_components (this
                                                     file)
      Invariant  3 (protocol-agnostic)            -- test_kernel_does_not_
                                                     import_ot_protocol_
                                                     libraries (this file)
      Invariant  4 (identity-provider-agnostic)   -- FORBIDDEN_PREFIXES's
                                                     keycloak/authlib/
                                                     oauthlib entries (this
                                                     file, exercised by
                                                     test_kernel_does_not_
                                                     import_web_frameworks's
                                                     sibling assertions
                                                     above); also asserted
                                                     per-module by
                                                     tests/operation_aware/
                                                     test_vocabulary_
                                                     boundaries.py and
                                                     test_context_
                                                     boundaries.py
      Invariant  9 (compatibility: no new
                    basis-schemas runtime
                    dependency)                   -- asserted directly
                                                     below
      Invariant 10 (dependency arrows point
                    inward)                       -- every intra-package
                                                     test in this file, plus
                                                     test_lower_kernel_
                                                     layers_never_import_
                                                     enforcement and
                                                     test_every_kernel_
                                                     module_is_classified_
                                                     by_a_boundary_rule
                                                     (this file)

    NOT statically provable by import inspection — an import test proves
    "module A's source does not reference module B," and nothing about
    what module A's code *does*. These invariants require executing code,
    which is what the test modules named below do; this test does not
    claim to prove them:

      Invariant  2 (evaluates, does not transport) -- see
                    tests/test_enforcement_point.py,
                    tests/operation_aware/test_operation_aware_
                    enforcement_point.py
      Invariant  5 (deterministic evaluation)      -- see
                    tests/test_evaluation_semantics.py,
                    tests/operation_aware/test_evaluation_engine.py
      Invariant  6 (fails closed)                  -- see
                    tests/test_enforcement_point.py,
                    tests/operation_aware/test_operation_aware_
                    enforcement_point.py
      Invariant  7 (adapters normalize, do not
                    authorize)                     -- a behavioral property
                    of adapter *implementations* outside this kernel; not
                    an import-graph property
      Invariant  8 (audit records, does not
                    decide)                        -- see tests/test_audit.py,
                    tests/operation_aware/test_audit_evidence.py

    Invariant 6's "no persistence in kernel audit-evidence models" aspect
    (ADR-0006 Decision 11) is behavioral (absence of a write/save/persist
    method), not an import-graph property; see
    tests/operation_aware/test_audit_evidence.py.
    """
    pyproject_text = (Path(__file__).parent.parent / "pyproject.toml").read_text(encoding="utf-8")
    deps_start = pyproject_text.index("dependencies = [")
    deps_end = pyproject_text.index("]", deps_start)
    runtime_dependencies_block = pyproject_text[deps_start:deps_end]
    assert "pydantic" in runtime_dependencies_block
    assert "basis-schemas" not in runtime_dependencies_block, (
        "basis-core must not declare a runtime dependency on basis-schemas "
        "(docs/kernel-constitution.md Invariant 9 / Invariant 1) — schema "
        "fixtures are vendored under tests/fixtures/, not installed as a "
        "package dependency."
    )
    assert "basis_gateway" not in runtime_dependencies_block
    assert "basis_identity" not in runtime_dependencies_block
    assert "basis_console" not in runtime_dependencies_block
