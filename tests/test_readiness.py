"""
tests/test_readiness.py — release readiness smoke tests.

Lightweight checks that confirm the package is correctly installed and
minimally functional as a distributable library:

  1. Version exposure     — basis_core.__version__ is present and matches pyproject.toml.
  2. Package import       — all six public subpackages are importable without error.
  3. Example execution    — the basic_evaluation example runs end-to-end without raising.
  4. v0.2.1 release state — the package version and release artifacts (readiness
                            review, changelog) agree that v0.2.1 is the current release.

These tests are intentionally minimal. They do not retest contracts already
covered by test_public_api.py, test_contract_snapshots.py, or test_evaluation_semantics.py.
Their purpose is to catch packaging regressions (missing files, broken __init__ imports,
example bit-rot) that unit tests would not catch, plus release-metadata drift
(version files disagreeing, a missing or stale changelog) that no other test covers.
"""

from __future__ import annotations

import importlib
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent

_SEMVER_PATTERN = re.compile(r"^\d+\.\d+\.\d+$")


def _pyproject_version() -> str:
    """Return pyproject.toml's project.version, however this interpreter can parse it.

    Prefers the stdlib `tomllib` (Python 3.11+). On Python 3.10 (the project's
    minimum supported version), `tomllib` does not exist; rather than adding a
    TOML-parsing dependency for a single field, this falls back to the same
    minimal source-line match `test_version_matches_pyproject` already uses.
    """
    pyproject_path = REPO_ROOT / "pyproject.toml"
    try:
        import tomllib  # type: ignore[import-not-found]
    except ModuleNotFoundError:
        content = pyproject_path.read_text(encoding="utf-8")
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("version") and "=" in stripped:
                return stripped.split("=", 1)[1].strip().strip('"').strip("'")
        pytest.fail("Could not find version declaration in pyproject.toml.")
    else:
        with pyproject_path.open("rb") as handle:
            data = tomllib.load(handle)
        return str(data["project"]["version"])


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


# ── 4. v0.2.1 release-state readiness ─────────────────────────────────────────


class TestV021ReleaseState:
    """The current release's version and release artifacts must agree.

    These checks are release-specific (they assert v0.2.1, not a general
    version-agreement rule — that's TestVersionExposure's job). They exist so
    that a future release bump that forgets to update the changelog, or that
    leaves the readiness review claiming release preparation is still pending,
    fails loudly here rather than shipping silently.
    """

    def test_pyproject_declares_0_2_1(self) -> None:
        assert _pyproject_version() == "0.2.1", (
            f"pyproject.toml declares version {_pyproject_version()!r}, expected '0.2.1'."
        )

    def test_runtime_version_is_0_2_1(self) -> None:
        import basis_core

        assert basis_core.__version__ == "0.2.1", (
            f"basis_core.__version__ is {basis_core.__version__!r}, expected '0.2.1'."
        )

    def test_metadata_and_runtime_versions_agree(self) -> None:
        import basis_core

        assert _pyproject_version() == basis_core.__version__, (
            f"pyproject.toml version ({_pyproject_version()!r}) does not match "
            f"basis_core.__version__ ({basis_core.__version__!r})."
        )

    def test_metadata_version_is_valid_semver(self) -> None:
        version = _pyproject_version()
        assert _SEMVER_PATTERN.match(version), (
            f"pyproject.toml version {version!r} is not a valid MAJOR.MINOR.PATCH semantic version."
        )

    def test_runtime_version_is_valid_semver(self) -> None:
        import basis_core

        assert _SEMVER_PATTERN.match(basis_core.__version__), (
            f"basis_core.__version__ {basis_core.__version__!r} is not a valid "
            "MAJOR.MINOR.PATCH semantic version."
        )

    def test_readiness_review_exists(self) -> None:
        assert (REPO_ROOT / "docs" / "v0.2-readiness-review.md").is_file(), (
            "docs/v0.2-readiness-review.md is missing. "
            "PR 44 depends on this review's recommendation to proceed."
        )

    def test_readiness_review_recommends_proceeding(self) -> None:
        content = (REPO_ROOT / "docs" / "v0.2-readiness-review.md").read_text(encoding="utf-8")
        assert "Recommendation: Proceed to PR 44" in content, (
            "docs/v0.2-readiness-review.md no longer contains the "
            "'Recommendation: Proceed to PR 44' line this release relied on."
        )

    def test_changelog_exists(self) -> None:
        assert (REPO_ROOT / "CHANGELOG.md").is_file(), (
            "CHANGELOG.md is missing. Every release must have a changelog entry."
        )

    def test_changelog_has_0_2_1_heading(self) -> None:
        content = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        assert "## [0.2.1]" in content, "CHANGELOG.md is missing a '## [0.2.1]' release heading."

    def test_changelog_does_not_claim_gateway_audit_event_is_kernel_owned(self) -> None:
        """GatewayAuditEvent is basis-gateway's artifact, never basis-core's.

        This does not parse the changelog's prose in general — it only guards
        against the specific, previously-seen mistake of describing
        GatewayAuditEvent as something the kernel produces or owns. Whitespace
        (including Markdown line-wrapping) is normalized before matching so a
        reflow of the prose doesn't spuriously break this check.
        """
        content = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        normalized = " ".join(content.split())
        if "GatewayAuditEvent" in normalized:
            not_kernel_owned = (
                "does not construct it" in normalized or "outside kernel ownership" in normalized
            )
            assert not_kernel_owned, (
                "CHANGELOG.md mentions GatewayAuditEvent without stating that it "
                "remains outside kernel ownership."
            )
        forbidden_claims = (
            "basis-core produces GatewayAuditEvent",
            "kernel produces GatewayAuditEvent",
            "GatewayAuditEvent is produced by basis-core",
        )
        for claim in forbidden_claims:
            assert claim not in normalized, f"CHANGELOG.md contains the forbidden claim: {claim!r}"

    def test_changelog_does_not_imply_basis_schemas_is_a_runtime_dependency(self) -> None:
        content = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        normalized = " ".join(content.split())
        if "basis-schemas" in normalized:
            assert "not a runtime dependency" in normalized, (
                "CHANGELOG.md mentions basis-schemas without stating that it is "
                "not a runtime dependency."
            )
        forbidden_claims = (
            "basis-schemas is a runtime dependency",
            "basis-schemas as a runtime dependency",
            "requires basis-schemas",
        )
        for claim in forbidden_claims:
            assert claim not in normalized, f"CHANGELOG.md contains the forbidden claim: {claim!r}"
