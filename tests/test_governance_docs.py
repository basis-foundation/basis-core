"""
tests/test_governance_docs.py — governance document integrity tests.

These tests verify that the breaking-change-discipline document exists, that
key governance documents cross-reference it, and that the PR template exists.

They are structural tests, not content tests: they check that the governance
scaffolding is in place, not that every word is correct. A failing test here
means a governance cross-reference was accidentally removed or a required file
is missing.

What these tests do NOT check:
- The correctness or completeness of the discipline document's content.
- Whether the process described has been followed for any specific change.
- Any behaviour of the Python code.
"""

from __future__ import annotations

import pathlib

REPO_ROOT = pathlib.Path(__file__).parent.parent


def _read(relative: str) -> str:
    return (REPO_ROOT / relative).read_text(encoding="utf-8")


class TestBreakingChangeDisciplineDoc:
    """The discipline doc must exist and be non-trivially populated."""

    def test_file_exists(self) -> None:
        assert (REPO_ROOT / "docs" / "breaking-change-discipline.md").is_file(), (
            "docs/breaking-change-discipline.md is missing. "
            "Create it or restore it from git history."
        )

    def test_file_is_not_empty(self) -> None:
        content = _read("docs/breaking-change-discipline.md")
        assert len(content) > 500, (
            "docs/breaking-change-discipline.md appears to be nearly empty. "
            "It should contain the full governance process."
        )

    def test_breaking_section_present(self) -> None:
        content = _read("docs/breaking-change-discipline.md")
        assert "## Breaking changes" in content, (
            "docs/breaking-change-discipline.md is missing the '## Breaking changes' section."
        )

    def test_additive_section_present(self) -> None:
        content = _read("docs/breaking-change-discipline.md")
        assert "## Additive changes" in content, (
            "docs/breaking-change-discipline.md is missing the '## Additive changes' section."
        )

    def test_required_process_section_present(self) -> None:
        content = _read("docs/breaking-change-discipline.md")
        assert "## Required process for breaking changes" in content, (
            "docs/breaking-change-discipline.md is missing the required-process section."
        )

    def test_pr_checklist_section_present(self) -> None:
        content = _read("docs/breaking-change-discipline.md")
        assert "## PR checklist" in content, (
            "docs/breaking-change-discipline.md is missing the PR checklist section."
        )

    def test_contract_surfaces_table_present(self) -> None:
        content = _read("docs/breaking-change-discipline.md")
        assert "## Contract surfaces" in content, (
            "docs/breaking-change-discipline.md is missing the contract surfaces table."
        )


class TestPrTemplate:
    """A PR template must exist with the contract-change checklist."""

    def test_pr_template_exists(self) -> None:
        assert (REPO_ROOT / ".github" / "pull_request_template.md").is_file(), (
            ".github/pull_request_template.md is missing. Create it or restore it from git history."
        )

    def test_pr_template_has_contract_checklist(self) -> None:
        content = _read(".github/pull_request_template.md")
        assert "Contract surface" in content or "contract surface" in content, (
            ".github/pull_request_template.md is missing the contract surface checklist. "
            "See docs/breaking-change-discipline.md for the required checklist items."
        )

    def test_pr_template_mentions_breaking_change_doc(self) -> None:
        content = _read(".github/pull_request_template.md")
        assert "breaking-change-discipline" in content, (
            ".github/pull_request_template.md should reference docs/breaking-change-discipline.md."
        )


class TestCrossReferences:
    """
    Key governance documents must cross-reference breaking-change-discipline.md.

    These tests catch accidental removal of cross-references during doc edits.
    If a test fails because you intentionally removed a cross-reference, add
    the reference back rather than removing the test.
    """

    def test_kernel_constitution_references_discipline(self) -> None:
        content = _read("docs/kernel-constitution.md")
        assert "breaking-change-discipline" in content, (
            "docs/kernel-constitution.md must reference docs/breaking-change-discipline.md. "
            "Add the cross-reference to the Purpose section and the relationship table."
        )

    def test_public_api_references_discipline(self) -> None:
        content = _read("docs/public-api.md")
        assert "breaking-change-discipline" in content, (
            "docs/public-api.md must reference docs/breaking-change-discipline.md. "
            "Add the cross-reference to the Cross-references paragraph at the top."
        )

    def test_compatibility_testing_references_discipline(self) -> None:
        content = _read("docs/compatibility-testing.md")
        assert "breaking-change-discipline" in content, (
            "docs/compatibility-testing.md must reference docs/breaking-change-discipline.md. "
            "Add the cross-reference to the Cross-references paragraph at the top."
        )

    def test_schema_versioning_references_discipline(self) -> None:
        content = _read("docs/schema-versioning.md")
        assert "breaking-change-discipline" in content, (
            "docs/schema-versioning.md must reference docs/breaking-change-discipline.md. "
            "Add the cross-reference to the Cross-references paragraph at the top."
        )
