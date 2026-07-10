#!/usr/bin/env python3
"""scripts/update_basis_schemas_snapshot.py — controlled, offline refresh tool
for the vendored ``basis-schemas`` operation-aware compatibility snapshot at
``tests/fixtures/basis-schemas/<release>/``.

What this script is
────────────────────
A narrow, deterministic copy-and-hash tool. Given an explicit, local,
already-checked-out ``basis-schemas`` source tree (a git checkout of an
immutable release tag, or a release archive extracted to disk), it copies
exactly the approved set of operation-aware contract schemas and canonical
compatibility-vector files into this repository's vendored snapshot
directory, and writes a deterministic ``manifest.json`` recording their
SHA-256 digests and the source release provenance.

What this script is not
────────────────────────
- Not a network client. It never fetches anything from GitHub, PyPI, or any
  other remote. ``--source`` must already exist on local disk.
- Not a schema validator or YAML parser. Files are copied and hashed as raw
  bytes; their contents are never interpreted.
- Not a general-purpose vendoring tool. The set of files it will copy is a
  fixed, hardcoded allowlist (see ``APPROVED_SCHEMA_CONTRACTS`` and
  ``APPROVED_COMPATIBILITY_SCENARIOS`` below) — expanding that allowlist is a
  reviewed source-code change to this script, not a runtime flag.
- Not a way to touch runtime package code. It only ever writes inside the
  destination snapshot directory (default
  ``tests/fixtures/basis-schemas/<release>/``); it never writes to
  ``src/basis_core/``.

Usage
─────
    python scripts/update_basis_schemas_snapshot.py \\
        --source /path/to/basis-schemas-v0.2.0 \\
        --release v0.2.0 \\
        --commit 1d3af3cfd38686173980cfb47f8fa44659a4e1c4

The ``--source`` tree must be a plain directory on local disk — for example
the result of ``git archive v0.2.0 | tar -x -C /path/to/dest`` or
``git -C /path/to/basis-schemas checkout v0.2.0`` in a scratch clone. This
script never invokes ``git`` itself and never reaches across the network.

Exit codes
──────────
0  success — snapshot written, manifest generated.
1  usage or validation error (missing/unexpected files, release mismatch,
   symlink/traversal rejection, etc.) — nothing is written on failure other
   than what has already been validated; the manifest is written last.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

# ── Fixed, reviewed allowlists ──────────────────────────────────────────────
# Expanding these tuples is itself a reviewed source change to this script —
# not a CLI flag — per this script's own "reject unexpected contract
# directories unless explicitly approved" requirement.

#: The 14 operation-aware contract directories under ``schemas/`` that this
#: repository vendors. Each directory is expected to contain exactly one file
#: named ``<contract-name>.yaml``.
APPROVED_SCHEMA_CONTRACTS: tuple[str, ...] = (
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

#: First-wave ``basis-schemas`` contract directories that are known to exist
#: under ``schemas/`` in the source tree but are deliberately NOT vendored by
#: this script (they mirror basis-core v0.1.0 contracts unchanged and are out
#: of scope for the operation-aware snapshot). Listed explicitly so the
#: "unexpected directory" check can distinguish "known, intentionally
#: excluded" from "unknown, possibly-unreviewed" contracts.
KNOWN_EXCLUDED_SCHEMA_CONTRACTS: tuple[str, ...] = (
    "action-string",
    "audit-event",
    "decision-request",
    "decision-response",
    "resource-identifier",
    "vocabulary",
)

#: The 5 canonical compatibility scenarios under
#: ``examples/operation-aware/compatibility/`` that this repository vendors,
#: mapped to the exact set of files each scenario directory must contain.
#: ``invalid-policy-bundle`` carries ``invalid-policy-bundle.yaml`` instead of
#: ``policy-bundle.yaml`` — it is intentionally not a valid bundle.
APPROVED_COMPATIBILITY_SCENARIOS: dict[str, tuple[str, ...]] = {
    "allow-basic": (
        "operation-aware-decision-request.yaml",
        "policy-bundle.yaml",
        "expected-evaluation-trace.yaml",
        "expected-operation-aware-decision-response.yaml",
        "expected-audit-evidence.yaml",
        "expected-gateway-audit-event.yaml",
    ),
    "deny-precedence": (
        "operation-aware-decision-request.yaml",
        "policy-bundle.yaml",
        "expected-evaluation-trace.yaml",
        "expected-operation-aware-decision-response.yaml",
        "expected-audit-evidence.yaml",
        "expected-gateway-audit-event.yaml",
    ),
    "default-deny": (
        "operation-aware-decision-request.yaml",
        "policy-bundle.yaml",
        "expected-evaluation-trace.yaml",
        "expected-operation-aware-decision-response.yaml",
        "expected-audit-evidence.yaml",
        "expected-gateway-audit-event.yaml",
    ),
    "not-applicable": (
        "operation-aware-decision-request.yaml",
        "policy-bundle.yaml",
        "expected-evaluation-trace.yaml",
        "expected-operation-aware-decision-response.yaml",
        "expected-audit-evidence.yaml",
        "expected-gateway-audit-event.yaml",
    ),
    "invalid-policy-bundle": (
        "operation-aware-decision-request.yaml",
        "invalid-policy-bundle.yaml",
        "expected-evaluation-trace.yaml",
        "expected-operation-aware-decision-response.yaml",
        "expected-audit-evidence.yaml",
        "expected-gateway-audit-event.yaml",
    ),
}

SOURCE_REPOSITORY = "basis-foundation/basis-schemas"
SNAPSHOT_PURPOSE = "basis-core operation-aware contract and compatibility test snapshot"

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DEST_ROOT = REPO_ROOT / "tests" / "fixtures" / "basis-schemas"

_COMMIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_RELEASE_RE = re.compile(r"^v(\d+\.\d+\.\d+)$")


class SnapshotUpdateError(Exception):
    """Raised for any validation failure. Caught once in main() -> exit(1)."""


@dataclass(frozen=True)
class PlannedFile:
    """One file this script intends to copy: source path -> dest-relative path."""

    source_path: Path
    dest_relative_path: str  # POSIX-style, relative to the snapshot root


# ── Argument parsing ────────────────────────────────────────────────────────


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Controlled, offline refresh of the vendored basis-schemas "
            "operation-aware compatibility snapshot."
        )
    )
    parser.add_argument(
        "--source",
        required=True,
        type=Path,
        help=(
            "Path to a local, already-checked-out basis-schemas source tree "
            "(a git checkout or extracted release archive) at the exact "
            "release being vendored. Never fetched over the network by this "
            "script."
        ),
    )
    parser.add_argument(
        "--release",
        required=True,
        help="The basis-schemas release tag being vendored, e.g. v0.2.0.",
    )
    parser.add_argument(
        "--commit",
        required=True,
        help="The exact 40-character basis-schemas commit SHA the release tag points to.",
    )
    parser.add_argument(
        "--dest",
        type=Path,
        default=None,
        help=(
            "Destination snapshot directory. Defaults to "
            "tests/fixtures/basis-schemas/<release>/ under the repository root."
        ),
    )
    parser.add_argument(
        "--captured-at",
        default=None,
        help=(
            "ISO-8601 UTC timestamp recorded in manifest.json as captured_at. "
            "Defaults to the source commit's committer date read from "
            "<source>/.git if available (deterministic across re-runs of the "
            "same commit); falls back to the current UTC time with a warning "
            "if unavailable."
        ),
    )
    return parser.parse_args(argv)


# ── Validation helpers ──────────────────────────────────────────────────────


def validate_release_and_commit(release: str, commit: str) -> str:
    """Validate --release/--commit syntax. Returns the bare version, e.g. '0.2.0'."""
    match = _RELEASE_RE.match(release)
    if not match:
        raise SnapshotUpdateError(
            f"--release {release!r} does not look like a release tag (expected 'vX.Y.Z')."
        )
    if not _COMMIT_SHA_RE.match(commit):
        raise SnapshotUpdateError(
            f"--commit {commit!r} does not look like a full 40-character lowercase hex SHA."
        )
    return match.group(1)


def verify_source_release_metadata(source: Path, expected_version: str) -> None:
    """Confirm --source is actually the claimed basis-schemas release.

    Reads the ``version = "..."`` line from <source>/pyproject.toml's
    [project] table with a targeted regex (no TOML parser dependency; this is
    a narrow internal sanity check, not general TOML parsing) and confirms it
    matches --release's bare version. Also cross-checks
    src/basis_schemas/__init__.py's ``__version__`` if present.
    """
    pyproject_path = source / "pyproject.toml"
    if not pyproject_path.is_file():
        raise SnapshotUpdateError(
            f"--source {source} does not look like a basis-schemas checkout: "
            f"{pyproject_path} not found."
        )
    pyproject_text = pyproject_path.read_text(encoding="utf-8")
    name_match = re.search(r'(?m)^name\s*=\s*"([^"]+)"', pyproject_text)
    if not name_match or name_match.group(1) != "basis-schemas":
        found_name = name_match.group(1) if name_match else None
        raise SnapshotUpdateError(
            f"--source {source}'s pyproject.toml does not declare "
            f'name = "basis-schemas" (found: {found_name!r}).'
        )
    version_match = re.search(r'(?m)^version\s*=\s*"([^"]+)"', pyproject_text)
    if not version_match:
        raise SnapshotUpdateError(f'Could not find a version = "..." line in {pyproject_path}.')
    found_version = version_match.group(1)
    if found_version != expected_version:
        raise SnapshotUpdateError(
            f"--release declares version {expected_version!r}, but "
            f"{pyproject_path} declares version {found_version!r}. Refusing "
            "to vendor a mismatched release."
        )

    init_path = source / "src" / "basis_schemas" / "__init__.py"
    if init_path.is_file():
        init_text = init_path.read_text(encoding="utf-8")
        init_version_match = re.search(r'__version__\s*:\s*Final\[str\]\s*=\s*"([^"]+)"', init_text)
        if not init_version_match:
            init_version_match = re.search(r'__version__\s*=\s*"([^"]+)"', init_text)
        if init_version_match and init_version_match.group(1) != expected_version:
            raise SnapshotUpdateError(
                f"--release declares version {expected_version!r}, but "
                f"{init_path} declares __version__ = "
                f"{init_version_match.group(1)!r}. Refusing to vendor a "
                "mismatched release."
            )


def reject_unsafe_path(path: Path, *, boundary: Path, label: str) -> None:
    """Reject symlinks and any path that would resolve outside `boundary`."""
    if path.is_symlink():
        raise SnapshotUpdateError(f"{label} {path} is a symlink; refusing to follow it.")
    resolved = path.resolve()
    resolved_boundary = boundary.resolve()
    try:
        resolved.relative_to(resolved_boundary)
    except ValueError as exc:
        raise SnapshotUpdateError(
            f"{label} {path} resolves outside of {boundary}; refusing (path traversal)."
        ) from exc


# ── Planning: figure out exactly what will be copied, and validate first ───


def plan_schema_files(source: Path) -> list[PlannedFile]:
    schemas_root = source / "schemas"
    if not schemas_root.is_dir():
        raise SnapshotUpdateError(f"{schemas_root} does not exist in --source.")

    actual_dirs = {
        p.name for p in schemas_root.iterdir() if p.is_dir() and not p.name.startswith(".")
    }
    approved = set(APPROVED_SCHEMA_CONTRACTS)
    known_excluded = set(KNOWN_EXCLUDED_SCHEMA_CONTRACTS)
    unexpected = actual_dirs - approved - known_excluded
    if unexpected:
        raise SnapshotUpdateError(
            "Unexpected schema contract director"
            + ("y" if len(unexpected) == 1 else "ies")
            + f" found under {schemas_root}: {sorted(unexpected)}. "
            "If this is an intentional new operation-aware contract, add it to "
            "APPROVED_SCHEMA_CONTRACTS in this script as a reviewed change."
        )

    missing = approved - actual_dirs
    if missing:
        raise SnapshotUpdateError(
            "Expected operation-aware schema contract director"
            + ("y" if len(missing) == 1 else "ies")
            + f" missing from {schemas_root}: {sorted(missing)}."
        )

    planned: list[PlannedFile] = []
    for contract in APPROVED_SCHEMA_CONTRACTS:
        contract_dir = schemas_root / contract
        reject_unsafe_path(contract_dir, boundary=schemas_root, label="Schema contract directory")
        expected_file = contract_dir / f"{contract}.yaml"
        if not expected_file.is_file():
            raise SnapshotUpdateError(
                f"Expected schema file {expected_file} does not exist "
                f"(contract directory {contract_dir} present but missing its yaml file)."
            )
        reject_unsafe_path(expected_file, boundary=schemas_root, label="Schema file")

        actual_files = sorted(p.name for p in contract_dir.iterdir() if p.is_file())
        if actual_files != [f"{contract}.yaml"]:
            raise SnapshotUpdateError(
                f"Schema contract directory {contract_dir} contains unexpected "
                f"file(s): {actual_files} (expected only ['{contract}.yaml'])."
            )

        planned.append(
            PlannedFile(
                source_path=expected_file,
                dest_relative_path=f"schemas/{contract}/{contract}.yaml",
            )
        )
    return planned


def plan_compatibility_files(source: Path) -> list[PlannedFile]:
    compat_root = source / "examples" / "operation-aware" / "compatibility"
    if not compat_root.is_dir():
        raise SnapshotUpdateError(f"{compat_root} does not exist in --source.")

    actual_dirs = {
        p.name for p in compat_root.iterdir() if p.is_dir() and not p.name.startswith(".")
    }
    approved = set(APPROVED_COMPATIBILITY_SCENARIOS)
    unexpected = actual_dirs - approved
    if unexpected:
        raise SnapshotUpdateError(
            "Unexpected compatibility scenario director"
            + ("y" if len(unexpected) == 1 else "ies")
            + f" found under {compat_root}: {sorted(unexpected)}. "
            "If this is an intentional new canonical scenario, add it to "
            "APPROVED_COMPATIBILITY_SCENARIOS in this script as a reviewed change."
        )

    missing = approved - actual_dirs
    if missing:
        raise SnapshotUpdateError(
            "Expected canonical compatibility scenario director"
            + ("y" if len(missing) == 1 else "ies")
            + f" missing from {compat_root}: {sorted(missing)}."
        )

    planned: list[PlannedFile] = []
    for scenario, expected_files in APPROVED_COMPATIBILITY_SCENARIOS.items():
        scenario_dir = compat_root / scenario
        reject_unsafe_path(scenario_dir, boundary=compat_root, label="Scenario directory")

        actual_files = sorted(p.name for p in scenario_dir.iterdir() if p.is_file())
        expected_sorted = sorted(expected_files)
        if actual_files != expected_sorted:
            missing_files = sorted(set(expected_files) - set(actual_files))
            extra_files = sorted(set(actual_files) - set(expected_files))
            raise SnapshotUpdateError(
                f"Scenario directory {scenario_dir} does not contain exactly "
                f"the expected artifact set. Missing: {missing_files}. "
                f"Unexpected: {extra_files}."
            )

        for filename in expected_files:
            file_path = scenario_dir / filename
            reject_unsafe_path(file_path, boundary=compat_root, label="Scenario artifact")
            planned.append(
                PlannedFile(
                    source_path=file_path,
                    dest_relative_path=f"compatibility/{scenario}/{filename}",
                )
            )
    return planned


# ── Execution: copy + hash + write manifest ─────────────────────────────────


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def copy_planned_files(planned: list[PlannedFile], dest_root: Path) -> dict[str, dict[str, str]]:
    files_manifest: dict[str, dict[str, str]] = {}
    for item in planned:
        dest_path = dest_root / item.dest_relative_path
        reject_unsafe_path(
            dest_path.parent if dest_path.parent.exists() else dest_root,
            boundary=dest_root,
            label="Destination directory",
        )
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(item.source_path, dest_path)
        files_manifest[item.dest_relative_path] = {"sha256": sha256_of(dest_path)}
    return dict(sorted(files_manifest.items()))


def resolve_captured_at(source: Path, explicit: str | None) -> str:
    if explicit:
        return explicit
    git_dir = source / ".git"
    if git_dir.exists():
        import subprocess

        try:
            result = subprocess.run(
                ["git", "-C", str(source), "log", "-1", "--format=%cI"],
                capture_output=True,
                text=True,
                timeout=10,
                check=True,
            )
            committer_date = result.stdout.strip()
            if committer_date:
                dt = datetime.fromisoformat(committer_date).astimezone(timezone.utc)
                return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:  # noqa: BLE001 - fall through to wall-clock fallback below
            pass
    print(
        "WARNING: could not determine a deterministic captured_at from "
        f"{source}/.git; falling back to current UTC time. Pass --captured-at "
        "explicitly for a fully deterministic re-run.",
        file=sys.stderr,
    )
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_manifest(
    dest_root: Path,
    *,
    release: str,
    commit: str,
    captured_at: str,
    files_manifest: dict[str, dict[str, str]],
) -> Path:
    manifest = {
        "source_repository": SOURCE_REPOSITORY,
        "source_release": release,
        "source_commit": commit,
        "captured_at": captured_at,
        "purpose": SNAPSHOT_PURPOSE,
        "files": files_manifest,
    }
    manifest_path = dest_root / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest_path


def clear_previous_vendored_files(dest_root: Path) -> None:
    """Remove previously vendored schemas/ and compatibility/ trees (if any).

    A refresh is always a full-directory replacement, never a hand patch (see
    the snapshot README). manifest.json and README.md, which are not
    vendored content, are left untouched.
    """
    for subdir in ("schemas", "compatibility"):
        target = dest_root / subdir
        if target.exists():
            shutil.rmtree(target)


# ── Entry point ──────────────────────────────────────────────────────────


def run(argv: list[str]) -> int:
    args = parse_args(argv)

    try:
        expected_version = validate_release_and_commit(args.release, args.commit)

        source = args.source.resolve()
        if not source.is_dir():
            raise SnapshotUpdateError(f"--source {source} does not exist or is not a directory.")

        verify_source_release_metadata(source, expected_version)

        dest_root = (args.dest or (DEFAULT_DEST_ROOT / args.release)).resolve()

        schema_files = plan_schema_files(source)
        compat_files = plan_compatibility_files(source)
        planned = schema_files + compat_files

        captured_at = resolve_captured_at(source, args.captured_at)

        clear_previous_vendored_files(dest_root)
        files_manifest = copy_planned_files(planned, dest_root)
        manifest_path = write_manifest(
            dest_root,
            release=args.release,
            commit=args.commit,
            captured_at=captured_at,
            files_manifest=files_manifest,
        )
    except SnapshotUpdateError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"Vendored {len(planned)} file(s) into {dest_root}")
    print(f"Manifest written to {manifest_path}")
    return 0


def main() -> None:
    sys.exit(run(sys.argv[1:]))


if __name__ == "__main__":
    main()
