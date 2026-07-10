"""
tests/test_basis_schemas_snapshot_provenance.py — release provenance tests
for the vendored `basis-schemas` v0.2.0 snapshot.

Asserts the *real* recorded provenance values, not merely that the fields
are present and non-empty. These values were independently confirmed at
plan-authoring time against the actual `basis-schemas` `v0.2.0` git tag (see
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`, Section 4,
which records the same commit SHA) and cross-checked directly against the
`v0.2.0` tag in the `basis-schemas` repository during this PR.

If this test ever needs to change, it means the snapshot is being
re-vendored against a new release — which must be a deliberate, reviewed PR
(see the snapshot README's "Refreshing this snapshot" section), not an
incidental edit.
"""

from __future__ import annotations

import re

from tests.helpers.basis_schemas_snapshot import load_snapshot_manifest

EXPECTED_SOURCE_REPOSITORY = "basis-foundation/basis-schemas"
EXPECTED_SOURCE_RELEASE = "v0.2.0"
EXPECTED_SOURCE_COMMIT = "1d3af3cfd38686173980cfb47f8fa44659a4e1c4"

_ISO8601_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class TestReleaseProvenance:
    def test_source_repository_is_basis_foundation_basis_schemas(self) -> None:
        manifest = load_snapshot_manifest()
        assert manifest["source_repository"] == EXPECTED_SOURCE_REPOSITORY

    def test_source_release_is_v0_2_0(self) -> None:
        manifest = load_snapshot_manifest()
        assert manifest["source_release"] == EXPECTED_SOURCE_RELEASE

    def test_source_commit_is_the_exact_tagged_commit_sha(self) -> None:
        manifest = load_snapshot_manifest()
        assert manifest["source_commit"] == EXPECTED_SOURCE_COMMIT

    def test_source_commit_is_a_full_40_character_lowercase_hex_sha(self) -> None:
        manifest = load_snapshot_manifest()
        commit = manifest["source_commit"]
        assert re.match(r"^[0-9a-f]{40}$", commit), (
            f"source_commit {commit!r} is not a full 40-character lowercase hex SHA "
            "(a short SHA, branch name, or 'main' is not an immutable pin)."
        )

    def test_captured_at_is_iso8601_utc(self) -> None:
        manifest = load_snapshot_manifest()
        captured_at = manifest["captured_at"]
        assert _ISO8601_UTC_RE.match(captured_at), (
            f"captured_at {captured_at!r} is not ISO-8601 UTC (expected YYYY-MM-DDTHH:MM:SSZ)."
        )

    def test_purpose_describes_test_and_compatibility_use(self) -> None:
        manifest = load_snapshot_manifest()
        purpose = manifest["purpose"].lower()
        assert "test" in purpose or "compatibility" in purpose

    def test_purpose_does_not_claim_runtime_or_evaluation_behavior(self) -> None:
        """The manifest must not claim this snapshot implements evaluation —
        it is a pinned test/development input only (see the snapshot
        README's ownership section and this PR's non-goals)."""
        manifest = load_snapshot_manifest()
        purpose = manifest["purpose"].lower()
        forbidden_terms = ("evaluat", "runtime dependency", "policy engine")
        for term in forbidden_terms:
            assert term not in purpose, (
                f"manifest 'purpose' field unexpectedly mentions {term!r}: {manifest['purpose']!r}"
            )
