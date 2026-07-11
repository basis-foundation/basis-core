"""
tests/operation_aware/test_yaml_loader_negative.py — negative tests for
`tests.helpers.operation_aware_contracts.load_yaml_document` and the
`require_*` structural helpers (Milestone 1, PR 4 of
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`).

All fixtures here are constructed in `tmp_path` — deliberately outside the
immutable pinned snapshot (`tests/fixtures/basis-schemas/v0.2.0/`) — so that
malformed/unsafe input can be exercised without ever touching, or requiring
a copy of, governed snapshot content.

`load_yaml_document`'s `boundary` parameter is optional precisely so these
tests can exercise "is this YAML well-formed and safe to parse" failures
(missing file, empty file, malformed YAML, multi-document, unsafe tags,
duplicate keys, invalid UTF-8) independently from "is this path allowed"
failures (absolute/`..`/symlink escape), which are exercised separately by
passing `boundary` explicitly.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers.operation_aware_contracts import (
    EmptyFixtureDocumentError,
    FixtureNotFoundError,
    InvalidYAMLError,
    MultiDocumentFixtureError,
    UnexpectedFixtureRootTypeError,
    UnsafeFixturePathError,
    load_yaml_document,
    require_mapping,
)

# ── Missing / wrong-kind path ─────────────────────────────────────────────


def test_missing_path_is_rejected(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist.yaml"
    with pytest.raises(FixtureNotFoundError):
        load_yaml_document(missing)


def test_directory_instead_of_file_is_rejected(tmp_path: Path) -> None:
    directory = tmp_path / "a-directory.yaml"
    directory.mkdir()
    with pytest.raises(FixtureNotFoundError):
        load_yaml_document(directory)


# ── Empty document ────────────────────────────────────────────────────────


def test_empty_file_is_rejected(tmp_path: Path) -> None:
    empty = tmp_path / "empty.yaml"
    empty.write_text("", encoding="utf-8")
    with pytest.raises(EmptyFixtureDocumentError):
        load_yaml_document(empty)


def test_whitespace_and_comment_only_file_is_rejected(tmp_path: Path) -> None:
    comment_only = tmp_path / "comment-only.yaml"
    comment_only.write_text("# just a comment\n\n", encoding="utf-8")
    with pytest.raises(EmptyFixtureDocumentError):
        load_yaml_document(comment_only)


def test_explicit_null_document_is_rejected(tmp_path: Path) -> None:
    """An explicit document-start marker with no content parses to a single
    `None` document, distinct from "no document at all" but equally empty
    for this loader's purposes."""
    explicit_null = tmp_path / "explicit-null.yaml"
    explicit_null.write_text("---\n", encoding="utf-8")
    with pytest.raises(EmptyFixtureDocumentError):
        load_yaml_document(explicit_null)


# ── Malformed YAML ────────────────────────────────────────────────────────


def test_malformed_yaml_is_rejected(tmp_path: Path) -> None:
    malformed = tmp_path / "malformed.yaml"
    malformed.write_text("key: [unclosed\n  nested: - not: valid\n", encoding="utf-8")
    with pytest.raises(InvalidYAMLError):
        load_yaml_document(malformed)


# ── Multi-document YAML ───────────────────────────────────────────────────


def test_multi_document_yaml_is_rejected(tmp_path: Path) -> None:
    multi = tmp_path / "multi.yaml"
    multi.write_text("a: 1\n---\nb: 2\n", encoding="utf-8")
    with pytest.raises(MultiDocumentFixtureError):
        load_yaml_document(multi)


# ── Unsafe YAML tags ───────────────────────────────────────────────────────


def test_unsafe_python_object_tag_is_rejected_not_executed(tmp_path: Path) -> None:
    """SafeLoader must refuse to construct this tag rather than execute
    anything. If this ever stopped raising, it would mean the loader had
    silently started constructing arbitrary Python objects from fixture
    content — a critical regression, not a minor one."""
    unsafe = tmp_path / "unsafe-tag.yaml"
    unsafe.write_text(
        "value: !!python/object/apply:builtins.list\n  - 1\n  - 2\n",
        encoding="utf-8",
    )
    with pytest.raises(InvalidYAMLError):
        load_yaml_document(unsafe)


# ── Duplicate mapping keys ─────────────────────────────────────────────────


def test_duplicate_top_level_keys_are_rejected(tmp_path: Path) -> None:
    """PyYAML's `SafeLoader` silently keeps the last value for a duplicate
    mapping key by default. This loader configures explicit rejection
    instead (see `_StrictSafeLoader` in
    `tests/helpers/operation_aware_contracts.py`) rather than silently
    accepting ambiguous fixture content."""
    duplicate = tmp_path / "duplicate-keys.yaml"
    duplicate.write_text("name: first\nname: second\n", encoding="utf-8")
    with pytest.raises(InvalidYAMLError):
        load_yaml_document(duplicate)


def test_duplicate_nested_keys_are_rejected(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate-nested-keys.yaml"
    duplicate.write_text(
        "contract:\n  name: example\n  name: example-again\n",
        encoding="utf-8",
    )
    with pytest.raises(InvalidYAMLError):
        load_yaml_document(duplicate)


# ── Invalid UTF-8 ───────────────────────────────────────────────────────────


def test_invalid_utf8_is_rejected(tmp_path: Path) -> None:
    invalid_utf8 = tmp_path / "invalid-utf8.yaml"
    invalid_utf8.write_bytes(b"key: \xff\xfe not valid utf-8\n")
    with pytest.raises(InvalidYAMLError):
        load_yaml_document(invalid_utf8)


# ── Unexpected scalar root (via require_mapping) ────────────────────────────


def test_unexpected_scalar_root_is_rejected_by_require_mapping(tmp_path: Path) -> None:
    scalar_root = tmp_path / "scalar-root.yaml"
    scalar_root.write_text("just_a_string\n", encoding="utf-8")
    document = load_yaml_document(scalar_root)
    assert document == "just_a_string"
    with pytest.raises(UnexpectedFixtureRootTypeError):
        require_mapping(document, context="scalar-root.yaml")


# ── Path-safety: boundary, `..` traversal, symlink escape ───────────────────


def test_absolute_path_outside_boundary_is_rejected(tmp_path: Path) -> None:
    boundary = tmp_path / "boundary"
    boundary.mkdir()
    outside = tmp_path / "outside.yaml"
    outside.write_text("a: 1\n", encoding="utf-8")

    with pytest.raises(UnsafeFixturePathError):
        load_yaml_document(outside, boundary=boundary)


def test_dot_dot_traversal_outside_boundary_is_rejected(tmp_path: Path) -> None:
    boundary = tmp_path / "boundary"
    boundary.mkdir()
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    target = outside_dir / "target.yaml"
    target.write_text("a: 1\n", encoding="utf-8")

    traversal_path = boundary / ".." / "outside" / "target.yaml"
    with pytest.raises(UnsafeFixturePathError):
        load_yaml_document(traversal_path, boundary=boundary)


def test_symlink_escape_outside_boundary_is_rejected(tmp_path: Path) -> None:
    boundary = tmp_path / "boundary"
    boundary.mkdir()
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    target = outside_dir / "target.yaml"
    target.write_text("a: 1\n", encoding="utf-8")

    escape_link = boundary / "escape.yaml"
    try:
        escape_link.symlink_to(target)
    except OSError:
        pytest.skip("Symlinks are not supported in this environment.")

    with pytest.raises(UnsafeFixturePathError):
        load_yaml_document(escape_link, boundary=boundary)


def test_path_inside_boundary_is_accepted(tmp_path: Path) -> None:
    boundary = tmp_path / "boundary"
    boundary.mkdir()
    inside = boundary / "inside.yaml"
    inside.write_text("a: 1\n", encoding="utf-8")

    document = load_yaml_document(inside, boundary=boundary)
    assert document == {"a": 1}
