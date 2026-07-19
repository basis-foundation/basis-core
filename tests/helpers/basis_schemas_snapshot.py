"""
tests.helpers.basis_schemas_snapshot — discovery and integrity helpers for the
vendored `basis-schemas` operation-aware snapshot. ``SNAPSHOT_RELEASE`` below
is the single active pointer: it currently selects
``tests/fixtures/basis-schemas/v0.2.1/`` (the corrected snapshot — see that
directory's ``README.md``). The prior ``v0.2.0/`` snapshot remains on disk,
immutable, for historical reference; it is simply no longer the release this
module resolves paths against.

This module is test-only. It is never imported by ``src/basis_core/`` (see
``tests/test_basis_schemas_snapshot_boundaries.py``) and is not part of the
`basis_core` public API (`docs/public-api.md`).

Scope
─────
This module provides *discovery* and *integrity* helpers — path lookups,
manifest loading, inventory enumeration, and path-safety checks. It
deliberately does NOT parse YAML content, validate contract shapes, or build
any operation-aware domain model. That is later, separate roadmap work (see
``docs/implementation/basis-core-v0.2-operation-aware-plan.md``, Milestone 1
PR 4 and Milestone 2 onward).

Usage
─────
    from tests.helpers.basis_schemas_snapshot import (
        get_schema_path,
        get_scenario_artifact,
        list_compatibility_scenarios,
        list_operation_aware_contracts,
        load_snapshot_manifest,
    )

    get_schema_path("operation-aware-decision-request")
    list_operation_aware_contracts()
    list_compatibility_scenarios()
    load_snapshot_manifest()
    get_scenario_artifact("allow-basic", "request")
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Final

# ── Location ─────────────────────────────────────────────────────────────

SNAPSHOT_RELEASE: Final[str] = "v0.2.1"

#: Absolute path to the vendored snapshot root for the pinned release.
SNAPSHOT_ROOT: Final[Path] = (
    Path(__file__).parent.parent / "fixtures" / "basis-schemas" / SNAPSHOT_RELEASE
)

SCHEMAS_ROOT: Final[Path] = SNAPSHOT_ROOT / "schemas"
COMPATIBILITY_ROOT: Final[Path] = SNAPSHOT_ROOT / "compatibility"
MANIFEST_PATH: Final[Path] = SNAPSHOT_ROOT / "manifest.json"

# ── Canonical inventory ─────────────────────────────────────────────────
# Single source of truth for "what must be present." Tests that assert
# inventory import these tuples rather than re-declaring them, so there is
# exactly one place that encodes "14 contracts" / "5 scenarios."

#: The 14 operation-aware contracts this snapshot vendors, in the same order
#: the operation-aware v0.2.0 plan documents them.
OPERATION_AWARE_CONTRACTS: Final[tuple[str, ...]] = (
    "contract-metadata",
    "redaction-classification",
    "reason-code",
    "identity-evidence-reference",
    "adapter-evidence-reference",
    "operation-aware-decision-request",
    "policy-condition",
    "policy-rule",
    "policy-bundle",
    "trace-rule-evidence",
    "evaluation-trace",
    "operation-aware-decision-response",
    "audit-evidence",
    "gateway-audit-event",
)

#: The 5 canonical compatibility scenarios this snapshot vendors.
COMPATIBILITY_SCENARIOS: Final[tuple[str, ...]] = (
    "allow-basic",
    "deny-precedence",
    "default-deny",
    "not-applicable",
    "invalid-policy-bundle",
)

#: Logical artifact name -> filename, for scenarios whose policy artifact is
#: named ``policy-bundle.yaml``. ``invalid-policy-bundle`` overrides the
#: ``policy_bundle`` entry below (see ``_artifact_filenames_for``).
_DEFAULT_ARTIFACT_FILENAMES: Final[dict[str, str]] = {
    "request": "operation-aware-decision-request.yaml",
    "policy_bundle": "policy-bundle.yaml",
    "expected_evaluation_trace": "expected-evaluation-trace.yaml",
    "expected_response": "expected-operation-aware-decision-response.yaml",
    "expected_audit_evidence": "expected-audit-evidence.yaml",
    "expected_gateway_audit_event": "expected-gateway-audit-event.yaml",
}

#: Kernel-boundary artifacts: inputs to, or expected outputs of, a
#: basis-core evaluator. Deliberately excludes
#: ``expected_gateway_audit_event`` — see ``GATEWAY_ONLY_SCENARIO_ARTIFACTS``
#: and the snapshot README's "Kernel-owned vs. gateway-only artifacts"
#: section. basis-core does not produce, consume, or own GatewayAuditEvent
#: records.
KERNEL_SCENARIO_ARTIFACTS: Final[tuple[str, ...]] = (
    "request",
    "policy_bundle",
    "expected_evaluation_trace",
    "expected_response",
    "expected_audit_evidence",
)

#: Cross-boundary reference-only artifacts. basis-gateway owns
#: GatewayAuditEvent, not basis-core. Tests must never treat these as
#: kernel-expected outputs.
GATEWAY_ONLY_SCENARIO_ARTIFACTS: Final[tuple[str, ...]] = ("expected_gateway_audit_event",)

ALL_SCENARIO_ARTIFACTS: Final[tuple[str, ...]] = (
    KERNEL_SCENARIO_ARTIFACTS + GATEWAY_ONLY_SCENARIO_ARTIFACTS
)


class SnapshotPathError(Exception):
    """Raised when a requested path does not exist or is unsafe."""


# ── Path safety ──────────────────────────────────────────────────────────


def _safe_relative_path(relative_path: str, *, boundary: Path) -> Path:
    """Resolve `relative_path` under `boundary`, rejecting escape attempts.

    Rejects absolute paths and any path (however constructed) that resolves
    outside of `boundary`, e.g. via ``..`` traversal or a symlink.
    """
    if Path(relative_path).is_absolute():
        raise SnapshotPathError(f"Refusing absolute manifest/lookup path: {relative_path!r}")

    candidate = (boundary / relative_path).resolve()
    resolved_boundary = boundary.resolve()
    try:
        candidate.relative_to(resolved_boundary)
    except ValueError as exc:
        raise SnapshotPathError(
            f"Path {relative_path!r} resolves outside snapshot boundary {boundary}."
        ) from exc
    return candidate


# ── Contract schema discovery ───────────────────────────────────────────


def list_operation_aware_contracts() -> list[str]:
    """Return the sorted list of contract directory names actually present
    under ``schemas/`` in the vendored snapshot (discovered from disk, not
    merely the ``OPERATION_AWARE_CONTRACTS`` constant)."""
    if not SCHEMAS_ROOT.is_dir():
        return []
    return sorted(p.name for p in SCHEMAS_ROOT.iterdir() if p.is_dir())


def get_schema_path(contract_name: str) -> Path:
    """Return the absolute path to a vendored contract's YAML file.

    Args:
        contract_name: kebab-case contract name, e.g.
            ``"operation-aware-decision-request"``.

    Raises:
        SnapshotPathError: if the contract directory or its YAML file does
            not exist, or if the resolved path would escape the snapshot.
    """
    relative = f"schemas/{contract_name}/{contract_name}.yaml"
    path = _safe_relative_path(relative, boundary=SNAPSHOT_ROOT)
    if not path.is_file():
        raise SnapshotPathError(
            f"No vendored schema file for contract {contract_name!r} at {path}."
        )
    return path


# ── Compatibility scenario discovery ────────────────────────────────────


def list_compatibility_scenarios() -> list[str]:
    """Return the sorted list of scenario directory names actually present
    under ``compatibility/`` in the vendored snapshot (discovered from disk,
    not merely the ``COMPATIBILITY_SCENARIOS`` constant)."""
    if not COMPATIBILITY_ROOT.is_dir():
        return []
    return sorted(p.name for p in COMPATIBILITY_ROOT.iterdir() if p.is_dir())


def _artifact_filenames_for(scenario: str) -> dict[str, str]:
    filenames = dict(_DEFAULT_ARTIFACT_FILENAMES)
    if scenario == "invalid-policy-bundle":
        filenames["policy_bundle"] = "invalid-policy-bundle.yaml"
    return filenames


def list_scenario_artifacts(scenario: str) -> tuple[str, ...]:
    """Return the logical artifact names expected for `scenario`.

    Every scenario carries the same six logical artifacts; only the
    filename backing ``policy_bundle`` differs for ``invalid-policy-bundle``
    (see ``get_scenario_artifact``).
    """
    return ALL_SCENARIO_ARTIFACTS


def get_scenario_artifact(scenario: str, artifact: str) -> Path:
    """Return the absolute path to one artifact file within a scenario.

    Args:
        scenario: one of ``COMPATIBILITY_SCENARIOS``, e.g. ``"allow-basic"``.
        artifact: one of ``ALL_SCENARIO_ARTIFACTS``, e.g. ``"request"`` or
            ``"expected_gateway_audit_event"``.

    Raises:
        SnapshotPathError: if the scenario or artifact is unknown, the file
            does not exist, or the resolved path would escape the snapshot.
    """
    filenames = _artifact_filenames_for(scenario)
    if artifact not in filenames:
        raise SnapshotPathError(
            f"Unknown scenario artifact {artifact!r}; expected one of {sorted(filenames)}."
        )
    relative = f"compatibility/{scenario}/{filenames[artifact]}"
    path = _safe_relative_path(relative, boundary=SNAPSHOT_ROOT)
    if not path.is_file():
        raise SnapshotPathError(
            f"No vendored artifact {artifact!r} for scenario {scenario!r} at {path}."
        )
    return path


# ── Manifest loading ─────────────────────────────────────────────────────


def load_snapshot_manifest() -> dict[str, Any]:
    """Load and parse ``manifest.json`` from the vendored snapshot.

    Raises:
        FileNotFoundError: if the manifest does not exist.
        ValueError: if the manifest does not parse as a JSON object.
    """
    if not MANIFEST_PATH.is_file():
        raise FileNotFoundError(f"Snapshot manifest not found: {MANIFEST_PATH}")
    raw = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"Snapshot manifest must be a JSON object, got {type(raw).__name__}.")
    return raw


def manifest_relative_paths() -> list[str]:
    """Return the sorted list of file paths recorded in the manifest."""
    manifest = load_snapshot_manifest()
    files = manifest.get("files", {})
    if not isinstance(files, dict):
        raise ValueError("Snapshot manifest 'files' entry must be a JSON object.")
    return sorted(files.keys())


def all_vendored_files() -> list[Path]:
    """Return every vendored file actually present on disk under
    ``schemas/`` and ``compatibility/`` (not the top-level ``manifest.json``
    or ``README.md``, which are not vendored content)."""
    files: list[Path] = []
    for root in (SCHEMAS_ROOT, COMPATIBILITY_ROOT):
        if root.is_dir():
            files.extend(p for p in root.rglob("*") if p.is_file())
    return sorted(files)
