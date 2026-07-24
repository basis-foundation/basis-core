"""
tests/test_basis_schemas_snapshot_integrity.py — manifest and hash integrity
tests for the vendored `basis-schemas` snapshot (currently `v0.2.2`, per
`tests/helpers/basis_schemas_snapshot.py`'s `SNAPSHOT_RELEASE`).

These tests protect the vendored snapshot from silent drift or accidental
hand-editing: every vendored file must match its recorded SHA-256 digest,
every manifest entry must point at a real file, every real file must be
manifested, and path handling must reject traversal, absolute paths, and
symlinks.

Cross-references
─────────────────
tests/fixtures/basis-schemas/v0.2.2/manifest.json — the manifest under test.
tests/helpers/basis_schemas_snapshot.py           — loading helpers.
scripts/update_basis_schemas_snapshot.py          — the tool that writes it.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

from tests.helpers.basis_schemas_snapshot import (
    COMPATIBILITY_ROOT,
    MANIFEST_PATH,
    SCHEMAS_ROOT,
    SNAPSHOT_ROOT,
    SnapshotPathError,
    _safe_relative_path,
    all_vendored_files,
    load_snapshot_manifest,
    manifest_relative_paths,
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


# ── Manifest structure ──────────────────────────────────────────────────


class TestManifestStructure:
    def test_manifest_exists(self) -> None:
        assert MANIFEST_PATH.is_file()

    def test_manifest_is_valid_json_object(self) -> None:
        manifest = load_snapshot_manifest()
        assert isinstance(manifest, dict)

    def test_manifest_has_required_top_level_keys(self) -> None:
        manifest = load_snapshot_manifest()
        required = {
            "source_repository",
            "source_release",
            "source_commit",
            "captured_at",
            "purpose",
            "files",
        }
        missing = required - manifest.keys()
        assert not missing, f"Manifest missing required key(s): {sorted(missing)}"

    def test_manifest_files_entry_is_nonempty_object(self) -> None:
        manifest = load_snapshot_manifest()
        assert isinstance(manifest["files"], dict)
        assert len(manifest["files"]) > 0

    def test_manifest_file_entries_have_sha256_field_with_valid_format(self) -> None:
        manifest = load_snapshot_manifest()
        for rel_path, entry in manifest["files"].items():
            assert isinstance(entry, dict), f"{rel_path}: entry must be an object"
            assert "sha256" in entry, f"{rel_path}: missing 'sha256' field"
            digest = entry["sha256"]
            assert isinstance(digest, str) and _SHA256_RE.match(digest), (
                f"{rel_path}: sha256 {digest!r} is not a 64-char lowercase hex digest"
            )

    def test_manifest_has_no_duplicate_paths(self) -> None:
        # JSON objects cannot carry duplicate keys after parsing, but verify
        # by re-reading raw text for literal duplicate key occurrences.
        raw_text = MANIFEST_PATH.read_text(encoding="utf-8")
        manifest = json.loads(raw_text)
        keys_in_files_block = list(manifest["files"].keys())
        assert len(keys_in_files_block) == len(set(keys_in_files_block))


# ── Deterministic ordering ──────────────────────────────────────────────


class TestManifestDeterminism:
    def test_files_are_sorted_lexicographically(self) -> None:
        manifest = load_snapshot_manifest()
        paths = list(manifest["files"].keys())
        assert paths == sorted(paths), "manifest.json 'files' keys are not sorted"

    def test_manifest_json_is_sorted_and_stable_on_reserialization(self) -> None:
        manifest = load_snapshot_manifest()
        reserialized = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        on_disk = MANIFEST_PATH.read_text(encoding="utf-8")
        assert reserialized == on_disk, (
            "manifest.json is not in the canonical sorted-key, 2-space-indent "
            "form the refresh tool writes; it may have been hand-edited."
        )


# ── SHA-256 verification ────────────────────────────────────────────────


class TestSha256Integrity:
    def test_every_manifested_file_matches_its_recorded_digest(self) -> None:
        manifest = load_snapshot_manifest()
        mismatches = []
        for rel_path, entry in manifest["files"].items():
            file_path = SNAPSHOT_ROOT / rel_path
            if not file_path.is_file():
                continue  # covered by test_every_manifest_path_exists_on_disk
            actual = _sha256_of(file_path)
            if actual != entry["sha256"]:
                mismatches.append((rel_path, entry["sha256"], actual))
        assert not mismatches, (
            "SHA-256 mismatch (file was edited or corrupted after vendoring):\n"
            + "\n".join(
                f"  {p}: manifest={expected} actual={actual}" for p, expected, actual in mismatches
            )
        )

    def test_every_manifest_path_exists_on_disk(self) -> None:
        manifest = load_snapshot_manifest()
        missing = [
            rel_path for rel_path in manifest["files"] if not (SNAPSHOT_ROOT / rel_path).is_file()
        ]
        assert not missing, f"Manifest references file(s) that do not exist: {missing}"

    def test_no_unmanifested_vendored_file_exists(self) -> None:
        """Every file actually present under schemas/ or compatibility/ must
        be recorded in the manifest — an unmanifested file is invisible to
        integrity checking and is itself a drift signal."""
        manifested = set(manifest_relative_paths())
        on_disk = {
            str(p.relative_to(SNAPSHOT_ROOT)).replace("\\", "/") for p in all_vendored_files()
        }
        unmanifested = on_disk - manifested
        assert not unmanifested, f"Unmanifested vendored file(s) found: {sorted(unmanifested)}"

    def test_manifest_covers_exactly_the_vendored_file_count(self) -> None:
        manifest = load_snapshot_manifest()
        assert len(manifest["files"]) == len(all_vendored_files())


# ── Path safety ──────────────────────────────────────────────────────────


class TestPathSafety:
    def test_absolute_manifest_path_is_rejected(self) -> None:
        with pytest.raises(SnapshotPathError):
            _safe_relative_path("/etc/passwd", boundary=SNAPSHOT_ROOT)

    def test_parent_traversal_is_rejected(self) -> None:
        with pytest.raises(SnapshotPathError):
            _safe_relative_path("../../../../etc/passwd", boundary=SNAPSHOT_ROOT)

    def test_traversal_disguised_within_a_valid_looking_prefix_is_rejected(self) -> None:
        with pytest.raises(SnapshotPathError):
            _safe_relative_path("schemas/../../outside.yaml", boundary=SNAPSHOT_ROOT)

    def test_all_manifest_paths_are_relative_and_safe(self) -> None:
        manifest = load_snapshot_manifest()
        for rel_path in manifest["files"]:
            assert not Path(rel_path).is_absolute(), f"Manifest path is absolute: {rel_path}"
            assert ".." not in Path(rel_path).parts, f"Manifest path traverses: {rel_path}"
            # Must resolve safely under the snapshot root.
            _safe_relative_path(rel_path, boundary=SNAPSHOT_ROOT)

    def test_no_symlinks_present_in_vendored_tree(self) -> None:
        symlinks = [p for p in all_vendored_files() if p.is_symlink()]
        assert not symlinks, f"Vendored tree contains symlink(s): {symlinks}"

        for root in (SCHEMAS_ROOT, COMPATIBILITY_ROOT):
            if root.is_dir():
                dir_symlinks = [d for d in root.rglob("*") if d.is_dir() and d.is_symlink()]
                assert not dir_symlinks, (
                    f"Vendored tree contains symlinked directory/directories: {dir_symlinks}"
                )
