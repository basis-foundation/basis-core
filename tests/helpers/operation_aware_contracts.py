"""
tests.helpers.operation_aware_contracts — safe, test-only YAML contract
loading and generic structural-validation utilities for the pinned
`basis-schemas` v0.2.0 operation-aware snapshot at
``tests/fixtures/basis-schemas/v0.2.0/``.

This module completes the remaining portion of roadmap PR 4
(`docs/implementation/basis-core-v0.2-operation-aware-plan.md`, Milestone 1):
the fixture-*discovery* half (path resolution, manifest loading, inventory
enumeration) was already delivered by
``tests/helpers/basis_schemas_snapshot.py``. This module adds the remaining
YAML-*parsing* half — turning a discovered path into parsed content — plus a
lightweight, generic structural-validation layer for asserting broad shape
(mapping/sequence/string-field presence and type) without encoding any
contract's business semantics.

This module is test-only. It is never imported by ``src/basis_core/`` (see
``tests/test_basis_schemas_snapshot_boundaries.py``) and is not part of the
`basis_core` public API (`docs/public-api.md`).

Scope
─────
This module deliberately does NOT:
  - implement operation-aware domain models or typed request/response types
  - implement semantic policy or request validation
  - implement condition-operator, selector-matching, or evaluation logic
  - implement trace or audit generation
  - reproduce `basis-schemas`' own YAML-schema semantics (patterns, enums,
    cross-field constraints) as a generic schema engine
  - expose any runtime schema-loading API from `basis_core`

It provides only:
  - a safe YAML loader for a single fixture file
  - generic mapping/sequence/scalar structural assertions
  - a structural (not semantic) check of the shared `contract:` metadata
    block every pinned contract publishes

Usage
─────
    from tests.helpers.operation_aware_contracts import (
        load_contract,
        load_scenario_artifact,
        load_yaml_document,
        require_mapping,
        require_mapping_field,
        require_optional_field,
        require_sequence,
        require_sequence_field,
        require_string_field,
        reject_unknown_fields,
        validate_contract_metadata,
    )

    document = load_contract("policy-bundle")
    metadata = validate_contract_metadata(document, context="policy-bundle")
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml

from tests.helpers.basis_schemas_snapshot import (
    SNAPSHOT_ROOT,
    get_scenario_artifact,
    get_schema_path,
)

# ── Exceptions ───────────────────────────────────────────────────────────
#
# A concise, test-helper-only hierarchy. These are NOT production exception
# types (basis-core's operation-aware production error hierarchy, if any, is
# separate, later roadmap work) — they exist only to give this module's
# callers and tests clear, distinguishable failure modes.


class FixtureLoadError(ValueError):
    """Base exception for test-only fixture loading/validation failures."""


class FixtureNotFoundError(FixtureLoadError):
    """Raised when a fixture path does not exist, or is not a regular file."""


class UnsafeFixturePathError(FixtureLoadError):
    """Raised when a fixture path is absolute where a boundary is enforced,
    resolves outside its required boundary via ``..`` traversal, or resolves
    outside its required boundary via a symlink."""


class InvalidYAMLError(FixtureLoadError):
    """Raised when fixture content is not valid UTF-8, does not parse as
    YAML, uses a YAML tag outside PyYAML's built-in safe constructor set, or
    contains duplicate mapping keys."""


class EmptyFixtureDocumentError(FixtureLoadError):
    """Raised when a YAML document is empty (no content, or content that
    parses to ``None``)."""


class MultiDocumentFixtureError(FixtureLoadError):
    """Raised when a YAML file contains more than one `---`-separated
    document. Multi-document fixtures are not supported by this loader."""


class UnexpectedFixtureRootTypeError(FixtureLoadError):
    """Raised by the `require_*` structural helpers when a loaded value is
    not the expected container type (mapping vs. sequence vs. scalar)."""


# ── Safe YAML loading ────────────────────────────────────────────────────


class _StrictSafeLoader(yaml.SafeLoader):
    """`yaml.SafeLoader` with duplicate-mapping-key rejection.

    `yaml.SafeLoader` already refuses to construct any tag outside its
    built-in safe set (e.g. ``!!python/object/apply:...``), which is why it
    is used here rather than `yaml.Loader` or `yaml.UnsafeLoader` — no
    Python object is ever constructed from fixture content.

    `yaml.SafeLoader` does NOT, by default, reject duplicate mapping keys —
    it silently keeps the last value, which could hide a malformed fixture.
    This subclass overrides `construct_mapping` to raise instead of
    silently overwriting. See `docs/implementation/basis-core-v0.2-operation-
    aware-plan.md` and this module's negative-loader tests for the explicit
    behavior this configures.
    """

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        if not isinstance(node, yaml.MappingNode):
            raise yaml.constructor.ConstructorError(
                None,
                None,
                f"expected a mapping node, but found {node.id}",
                node.start_mark,
            )
        mapping: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in mapping:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"found duplicate key: {key!r}",
                    key_node.start_mark,
                )
            value = self.construct_object(value_node, deep=deep)
            mapping[key] = value
        return mapping


def _reject_unsafe_path(path: Path, *, boundary: Path) -> None:
    """Reject `path` if it is not a descendant of `boundary`.

    Resolving both sides (which follows symlinks and normalizes `..`
    components) means this single check catches absolute-path escapes,
    `..`-traversal escapes, and symlink escapes uniformly.
    """
    resolved_boundary = boundary.resolve()
    resolved_path = path.resolve()
    try:
        resolved_path.relative_to(resolved_boundary)
    except ValueError as exc:
        raise UnsafeFixturePathError(
            f"Path {path} resolves to {resolved_path}, which is outside the "
            f"permitted boundary {resolved_boundary}."
        ) from exc


def load_yaml_document(path: Path, *, boundary: Path | None = None) -> object:
    """Safely load exactly one YAML document from `path`.

    Args:
        path: absolute or relative path to a single YAML file.
        boundary: if given, `path` must resolve to a descendant of this
            directory (absolute-path, `..`-traversal, and symlink escapes
            are all rejected). If omitted, no boundary is enforced — callers
            that need boundary enforcement (see `load_contract` and
            `load_scenario_artifact`) pass it explicitly; this keeps
            `load_yaml_document` itself usable in negative tests against
            arbitrary temporary files outside any pinned snapshot.

    Returns:
        The single parsed YAML document — a `dict`, `list`, or scalar,
        whatever the file's root node produces. Structural expectations
        (e.g. "must be a mapping") are asserted separately by the
        `require_*` helpers below, not by this function.

    Raises:
        UnsafeFixturePathError: `boundary` was given and `path` resolves
            outside it.
        FixtureNotFoundError: `path` does not exist, or is not a regular
            file (e.g. a directory).
        InvalidYAMLError: the file is not valid UTF-8, does not parse as
            YAML, uses an unsupported YAML tag, or contains duplicate
            mapping keys.
        EmptyFixtureDocumentError: the file contains no YAML document, or
            its single document parses to `None`.
        MultiDocumentFixtureError: the file contains more than one
            `---`-separated YAML document.
    """
    if boundary is not None:
        _reject_unsafe_path(path, boundary=boundary)

    if not path.exists():
        raise FixtureNotFoundError(f"Fixture file not found: {path}")
    if not path.is_file():
        raise FixtureNotFoundError(f"Expected a regular file, found something else: {path}")

    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        raise FixtureLoadError(f"Unable to read fixture file {path}: {exc}") from exc

    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvalidYAMLError(f"Fixture file {path} is not valid UTF-8: {exc}") from exc

    try:
        documents = list(yaml.load_all(text, Loader=_StrictSafeLoader))
    except yaml.YAMLError as exc:
        raise InvalidYAMLError(f"Fixture file {path} is not valid YAML: {exc}") from exc

    if len(documents) == 0:
        raise EmptyFixtureDocumentError(f"Fixture file {path} contains no YAML document.")
    if len(documents) > 1:
        raise MultiDocumentFixtureError(
            f"Fixture file {path} contains {len(documents)} YAML documents; "
            "multi-document fixtures are not supported by this loader."
        )

    document = documents[0]
    if document is None:
        raise EmptyFixtureDocumentError(f"Fixture file {path} parses to an empty YAML document.")

    return document


# ── Snapshot-aware loading ───────────────────────────────────────────────
#
# These reuse the existing discovery helpers (`get_schema_path`,
# `get_scenario_artifact`), which already resolve a contract/scenario/
# artifact name to a path safely, then additionally enforce the snapshot
# boundary again here — belt-and-suspenders, not a substitute.


def load_contract(contract_name: str) -> dict[str, object]:
    """Load one pinned contract YAML by its kebab-case name (e.g.
    ``"policy-bundle"``) and require it to have a mapping root.

    Raises:
        SnapshotPathError: from `get_schema_path`, if `contract_name` is
            unknown or its file is missing.
        UnsafeFixturePathError, FixtureNotFoundError, InvalidYAMLError,
        EmptyFixtureDocumentError, MultiDocumentFixtureError: from
            `load_yaml_document`.
        UnexpectedFixtureRootTypeError: the contract file's root is not a
            mapping.
    """
    path = get_schema_path(contract_name)
    document = load_yaml_document(path, boundary=SNAPSHOT_ROOT)
    return require_mapping(document, context=f"contract {contract_name!r}")


def load_scenario_artifact(
    scenario_name: str,
    artifact_name: str,
) -> dict[str, object] | list[object] | object:
    """Load one compatibility-scenario artifact YAML (e.g. scenario
    ``"allow-basic"``, artifact ``"request"``).

    Unlike `load_contract`, this does not assert a mapping root — every
    pinned artifact happens to have one today, but this function makes no
    such promise on the caller's behalf; use `require_mapping` explicitly
    if a mapping root is required.

    Raises:
        SnapshotPathError: from `get_scenario_artifact`, if `scenario_name`
            or `artifact_name` is unknown, or the file is missing.
        UnsafeFixturePathError, FixtureNotFoundError, InvalidYAMLError,
        EmptyFixtureDocumentError, MultiDocumentFixtureError: from
            `load_yaml_document`.
    """
    path = get_scenario_artifact(scenario_name, artifact_name)
    return load_yaml_document(path, boundary=SNAPSHOT_ROOT)


# ── Generic structural-validation helpers ────────────────────────────────
#
# Deliberately generic: no field names, patterns, or enums from any specific
# contract are hard-coded here (`validate_contract_metadata` below is the one
# exception, and even it checks only the four fields every pinned contract's
# `contract:` block already shares). These helpers never coerce a value into
# the "right" type — a wrong type is always an error, never silently
# accepted or converted.


def require_mapping(value: object, *, context: str) -> dict[str, object]:
    """Assert `value` is a mapping (`dict`) and return it unchanged."""
    if not isinstance(value, dict):
        raise UnexpectedFixtureRootTypeError(
            f"{context}: expected a mapping, got {type(value).__name__}."
        )
    return value


def require_sequence(value: object, *, context: str) -> list[object]:
    """Assert `value` is a sequence (`list`) and return it unchanged.

    Strings are deliberately not treated as sequences here, even though
    Python's `Sequence` ABC would accept them — a YAML scalar string is
    never a structurally valid stand-in for a YAML list in these fixtures.
    """
    if not isinstance(value, list):
        raise UnexpectedFixtureRootTypeError(
            f"{context}: expected a sequence, got {type(value).__name__}."
        )
    return value


def require_string_field(
    mapping: Mapping[str, object],
    field: str,
    *,
    context: str,
) -> str:
    """Assert `mapping[field]` is present and a `str`; return it unchanged."""
    if field not in mapping:
        raise FixtureLoadError(f"{context}: missing required field {field!r}.")
    value = mapping[field]
    if not isinstance(value, str):
        raise FixtureLoadError(
            f"{context}: field {field!r} must be a string, got {type(value).__name__}."
        )
    return value


def require_mapping_field(
    mapping: Mapping[str, object],
    field: str,
    *,
    context: str,
) -> dict[str, object]:
    """Assert `mapping[field]` is present and itself a mapping."""
    if field not in mapping:
        raise FixtureLoadError(f"{context}: missing required field {field!r}.")
    return require_mapping(mapping[field], context=f"{context}.{field}")


def require_sequence_field(
    mapping: Mapping[str, object],
    field: str,
    *,
    context: str,
) -> list[object]:
    """Assert `mapping[field]` is present and itself a sequence."""
    if field not in mapping:
        raise FixtureLoadError(f"{context}: missing required field {field!r}.")
    return require_sequence(mapping[field], context=f"{context}.{field}")


def require_optional_field(
    mapping: Mapping[str, object],
    field: str,
    *,
    expected_type: type | tuple[type, ...],
    context: str,
) -> object | None:
    """Return `mapping[field]` if present, after asserting its type; `None`
    if the field is absent entirely. Absence and "structurally wrong type"
    are distinct: absence returns `None`, a present-but-wrong-typed value
    always raises."""
    if field not in mapping:
        return None
    value = mapping[field]
    if not isinstance(value, expected_type):
        type_name = getattr(expected_type, "__name__", str(expected_type))
        raise FixtureLoadError(
            f"{context}: optional field {field!r} must be {type_name}, got {type(value).__name__}."
        )
    return value


def reject_unknown_fields(
    mapping: Mapping[str, object],
    *,
    allowed: Sequence[str],
    context: str,
) -> None:
    """Raise if `mapping` contains any key outside `allowed`."""
    unknown = sorted(set(mapping) - set(allowed))
    if unknown:
        raise FixtureLoadError(
            f"{context}: unknown field(s) {unknown} not in allowed set {sorted(allowed)}."
        )


# ── Shared contract metadata validation ──────────────────────────────────


def validate_contract_metadata(document: object, *, context: str) -> dict[str, object]:
    """Structurally validate the `contract:` metadata block shared by every
    pinned operation-aware contract (see
    ``tests/fixtures/basis-schemas/v0.2.0/schemas/contract-metadata/
    contract-metadata.yaml``, the published contract this block itself
    formalizes).

    Checks only structural presence and type — required presence of
    `contract`, `contract.name`, `contract.version`, `contract.lifecycle`
    as strings, and `contract.depends_on`, when present, as a list of
    strings. This deliberately does NOT validate `name`'s kebab-case
    pattern, `version`'s semver pattern, `lifecycle`'s closed enum values,
    or any other field the `contract-metadata` contract itself defines —
    reproducing that contract's own field-level rules here would fork it,
    not consume it. Callers that need those checks should validate against
    the vendored `contract-metadata.yaml` fixture directly, not against
    rules hard-coded in this test helper.

    Returns:
        The `contract:` sub-mapping, unchanged.

    Raises:
        UnexpectedFixtureRootTypeError: `document` is not a mapping, or
            `contract` is present but not itself a mapping.
        FixtureLoadError: `contract`, `contract.name`, `contract.version`,
            or `contract.lifecycle` is missing or wrong-typed; or
            `contract.depends_on` is present but not a list of strings.
    """
    root = require_mapping(document, context=context)
    contract = require_mapping_field(root, "contract", context=context)
    metadata_context = f"{context}.contract"

    require_string_field(contract, "name", context=metadata_context)
    require_string_field(contract, "version", context=metadata_context)
    require_string_field(contract, "lifecycle", context=metadata_context)

    depends_on = require_optional_field(
        contract, "depends_on", expected_type=list, context=metadata_context
    )
    if depends_on is not None:
        for index, item in enumerate(depends_on):
            if not isinstance(item, str):
                raise FixtureLoadError(
                    f"{metadata_context}.depends_on[{index}]: expected a string, "
                    f"got {type(item).__name__}."
                )

    return contract
