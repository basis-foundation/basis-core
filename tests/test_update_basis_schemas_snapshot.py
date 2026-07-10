"""
tests/test_update_basis_schemas_snapshot.py — tests for the offline refresh
tool at `scripts/update_basis_schemas_snapshot.py`.

These tests exercise the tool against small, synthetic, on-disk fake
`basis-schemas` source trees (never the real vendored snapshot and never
the network) to prove the tool's validation and copy/hash/manifest logic
independent of the currently-vendored v0.2.0 content.

The tool module is loaded directly from its file path (it lives under
`scripts/`, not an importable package) via `importlib.util`.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "update_basis_schemas_snapshot.py"


def _load_script_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("update_basis_schemas_snapshot", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Register in sys.modules before exec: the module uses @dataclass, whose
    # machinery looks up sys.modules[cls.__module__] during class creation.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


tool = _load_script_module()

VALID_COMMIT = "1d3af3cfd38686173980cfb47f8fa44659a4e1c4"
VALID_RELEASE = "v0.2.0"
MINIMAL_SCHEMA_YAML = "contract:\n  name: {name}\n  version: 0.1.0\n"


def _write_pyproject(root: Path, *, name: str = "basis-schemas", version: str = "0.2.0") -> None:
    (root / "pyproject.toml").write_text(
        f'[project]\nname = "{name}"\nversion = "{version}"\n', encoding="utf-8"
    )


def _write_init(root: Path, *, version: str = "0.2.0") -> None:
    init_dir = root / "src" / "basis_schemas"
    init_dir.mkdir(parents=True, exist_ok=True)
    (init_dir / "__init__.py").write_text(f'__version__: "str" = "{version}"\n', encoding="utf-8")


def _write_schema_contracts(root: Path, contracts: tuple[str, ...]) -> None:
    schemas_root = root / "schemas"
    for contract in contracts:
        contract_dir = schemas_root / contract
        contract_dir.mkdir(parents=True, exist_ok=True)
        (contract_dir / f"{contract}.yaml").write_text(
            MINIMAL_SCHEMA_YAML.format(name=contract), encoding="utf-8"
        )


def _write_compatibility_scenarios(root: Path, scenarios: dict[str, tuple[str, ...]]) -> None:
    compat_root = root / "examples" / "operation-aware" / "compatibility"
    for scenario, files in scenarios.items():
        scenario_dir = compat_root / scenario
        scenario_dir.mkdir(parents=True, exist_ok=True)
        for filename in files:
            (scenario_dir / filename).write_text(f"# {scenario}/{filename}\n", encoding="utf-8")


def _build_valid_source_tree(tmp_path: Path) -> Path:
    source = tmp_path / "basis-schemas-src"
    source.mkdir()
    _write_pyproject(source)
    _write_init(source)
    _write_schema_contracts(source, tool.APPROVED_SCHEMA_CONTRACTS)
    _write_compatibility_scenarios(source, tool.APPROVED_COMPATIBILITY_SCENARIOS)
    return source


# ── Happy path ───────────────────────────────────────────────────────────


class TestHappyPath:
    def test_refresh_succeeds_and_writes_manifest(self, tmp_path: Path) -> None:
        source = _build_valid_source_tree(tmp_path)
        dest = tmp_path / "dest"

        exit_code = tool.run(
            [
                "--source",
                str(source),
                "--release",
                VALID_RELEASE,
                "--commit",
                VALID_COMMIT,
                "--dest",
                str(dest),
                "--captured-at",
                "2026-07-10T15:33:39Z",
            ]
        )

        assert exit_code == 0
        manifest_path = dest / "manifest.json"
        assert manifest_path.is_file()
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        assert manifest["source_release"] == VALID_RELEASE
        assert manifest["source_commit"] == VALID_COMMIT
        assert manifest["captured_at"] == "2026-07-10T15:33:39Z"
        assert len(manifest["files"]) == 14 + 5 * 6

    def test_refresh_copies_every_expected_file_byte_identical(self, tmp_path: Path) -> None:
        source = _build_valid_source_tree(tmp_path)
        dest = tmp_path / "dest"
        tool.run(
            [
                "--source",
                str(source),
                "--release",
                VALID_RELEASE,
                "--commit",
                VALID_COMMIT,
                "--dest",
                str(dest),
                "--captured-at",
                "2026-07-10T15:33:39Z",
            ]
        )
        rel = Path("schemas") / "contract-metadata" / "contract-metadata.yaml"
        assert (source / rel).read_bytes() == (dest / rel).read_bytes()

    def test_refresh_is_deterministic_across_reruns(self, tmp_path: Path) -> None:
        source = _build_valid_source_tree(tmp_path)
        dest = tmp_path / "dest"
        args = [
            "--source",
            str(source),
            "--release",
            VALID_RELEASE,
            "--commit",
            VALID_COMMIT,
            "--dest",
            str(dest),
            "--captured-at",
            "2026-07-10T15:33:39Z",
        ]
        tool.run(args)
        first_manifest = (dest / "manifest.json").read_text(encoding="utf-8")
        tool.run(args)
        second_manifest = (dest / "manifest.json").read_text(encoding="utf-8")
        assert first_manifest == second_manifest

    def test_refresh_replaces_stale_previously_vendored_files(self, tmp_path: Path) -> None:
        """A refresh is a full-directory replacement: a file that existed in
        a previous vendored copy but not the new source must be gone
        afterward, not merged/left behind."""
        source = _build_valid_source_tree(tmp_path)
        dest = tmp_path / "dest"
        stale_file = dest / "schemas" / "stale-contract" / "stale-contract.yaml"
        stale_file.parent.mkdir(parents=True, exist_ok=True)
        stale_file.write_text("stale", encoding="utf-8")

        exit_code = tool.run(
            [
                "--source",
                str(source),
                "--release",
                VALID_RELEASE,
                "--commit",
                VALID_COMMIT,
                "--dest",
                str(dest),
                "--captured-at",
                "2026-07-10T15:33:39Z",
            ]
        )
        assert exit_code == 0
        assert not stale_file.exists()


# ── Failure paths ────────────────────────────────────────────────────────


class TestFailurePaths:
    def test_missing_source_directory_fails_with_nonzero_exit(self, tmp_path: Path) -> None:
        missing_source = tmp_path / "does-not-exist"
        exit_code = tool.run(
            [
                "--source",
                str(missing_source),
                "--release",
                VALID_RELEASE,
                "--commit",
                VALID_COMMIT,
                "--dest",
                str(tmp_path / "dest"),
            ]
        )
        assert exit_code == 1

    def test_wrong_release_version_fails(self, tmp_path: Path) -> None:
        source = tmp_path / "basis-schemas-src"
        source.mkdir()
        _write_pyproject(source, version="0.1.0")  # declares 0.1.0, not 0.2.0
        _write_schema_contracts(source, tool.APPROVED_SCHEMA_CONTRACTS)
        _write_compatibility_scenarios(source, tool.APPROVED_COMPATIBILITY_SCENARIOS)

        exit_code = tool.run(
            [
                "--source",
                str(source),
                "--release",
                VALID_RELEASE,  # v0.2.0
                "--commit",
                VALID_COMMIT,
                "--dest",
                str(tmp_path / "dest"),
            ]
        )
        assert exit_code == 1
        assert not (tmp_path / "dest" / "manifest.json").exists()

    def test_wrong_package_name_fails(self, tmp_path: Path) -> None:
        source = tmp_path / "basis-schemas-src"
        source.mkdir()
        _write_pyproject(source, name="some-other-package")
        _write_schema_contracts(source, tool.APPROVED_SCHEMA_CONTRACTS)
        _write_compatibility_scenarios(source, tool.APPROVED_COMPATIBILITY_SCENARIOS)

        exit_code = tool.run(
            [
                "--source",
                str(source),
                "--release",
                VALID_RELEASE,
                "--commit",
                VALID_COMMIT,
                "--dest",
                str(tmp_path / "dest"),
            ]
        )
        assert exit_code == 1

    def test_incomplete_source_missing_a_contract_fails(self, tmp_path: Path) -> None:
        source = tmp_path / "basis-schemas-src"
        source.mkdir()
        _write_pyproject(source)
        incomplete_contracts = tool.APPROVED_SCHEMA_CONTRACTS[:-1]  # drop the last one
        _write_schema_contracts(source, incomplete_contracts)
        _write_compatibility_scenarios(source, tool.APPROVED_COMPATIBILITY_SCENARIOS)

        exit_code = tool.run(
            [
                "--source",
                str(source),
                "--release",
                VALID_RELEASE,
                "--commit",
                VALID_COMMIT,
                "--dest",
                str(tmp_path / "dest"),
            ]
        )
        assert exit_code == 1
        assert not (tmp_path / "dest" / "manifest.json").exists()

    def test_incomplete_source_missing_a_scenario_artifact_fails(self, tmp_path: Path) -> None:
        source = tmp_path / "basis-schemas-src"
        source.mkdir()
        _write_pyproject(source)
        _write_schema_contracts(source, tool.APPROVED_SCHEMA_CONTRACTS)
        scenarios = dict(tool.APPROVED_COMPATIBILITY_SCENARIOS)
        scenarios["allow-basic"] = scenarios["allow-basic"][:-1]  # drop one artifact
        _write_compatibility_scenarios(source, scenarios)

        exit_code = tool.run(
            [
                "--source",
                str(source),
                "--release",
                VALID_RELEASE,
                "--commit",
                VALID_COMMIT,
                "--dest",
                str(tmp_path / "dest"),
            ]
        )
        assert exit_code == 1

    def test_unexpected_contract_directory_fails(self, tmp_path: Path) -> None:
        source = _build_valid_source_tree(tmp_path)
        rogue_dir = source / "schemas" / "totally-unapproved-contract"
        rogue_dir.mkdir()
        (rogue_dir / "totally-unapproved-contract.yaml").write_text("x: 1\n", encoding="utf-8")

        exit_code = tool.run(
            [
                "--source",
                str(source),
                "--release",
                VALID_RELEASE,
                "--commit",
                VALID_COMMIT,
                "--dest",
                str(tmp_path / "dest"),
            ]
        )
        assert exit_code == 1
        assert not (tmp_path / "dest" / "manifest.json").exists()

    def test_unexpected_scenario_directory_fails(self, tmp_path: Path) -> None:
        source = _build_valid_source_tree(tmp_path)
        rogue_scenario = (
            source
            / "examples"
            / "operation-aware"
            / "compatibility"
            / "totally-unapproved-scenario"
        )
        rogue_scenario.mkdir()
        (rogue_scenario / "operation-aware-decision-request.yaml").write_text(
            "x: 1\n", encoding="utf-8"
        )

        exit_code = tool.run(
            [
                "--source",
                str(source),
                "--release",
                VALID_RELEASE,
                "--commit",
                VALID_COMMIT,
                "--dest",
                str(tmp_path / "dest"),
            ]
        )
        assert exit_code == 1

    def test_unexpected_extra_file_within_scenario_directory_fails(self, tmp_path: Path) -> None:
        source = _build_valid_source_tree(tmp_path)
        scenario_dir = source / "examples" / "operation-aware" / "compatibility" / "allow-basic"
        (scenario_dir / "unexpected-extra-file.yaml").write_text("x: 1\n", encoding="utf-8")

        exit_code = tool.run(
            [
                "--source",
                str(source),
                "--release",
                VALID_RELEASE,
                "--commit",
                VALID_COMMIT,
                "--dest",
                str(tmp_path / "dest"),
            ]
        )
        assert exit_code == 1

    def test_malformed_release_flag_fails(self, tmp_path: Path) -> None:
        source = _build_valid_source_tree(tmp_path)
        exit_code = tool.run(
            [
                "--source",
                str(source),
                "--release",
                "not-a-release-tag",
                "--commit",
                VALID_COMMIT,
                "--dest",
                str(tmp_path / "dest"),
            ]
        )
        assert exit_code == 1

    def test_malformed_commit_flag_fails(self, tmp_path: Path) -> None:
        source = _build_valid_source_tree(tmp_path)
        exit_code = tool.run(
            [
                "--source",
                str(source),
                "--release",
                VALID_RELEASE,
                "--commit",
                "not-a-real-sha",
                "--dest",
                str(tmp_path / "dest"),
            ]
        )
        assert exit_code == 1

    @pytest.mark.skipif(
        sys.platform == "win32", reason="symlinks require elevated privileges on Windows"
    )
    def test_symlinked_schema_file_is_rejected(self, tmp_path: Path) -> None:
        source = _build_valid_source_tree(tmp_path)
        target_file = source / "schemas" / "contract-metadata" / "contract-metadata.yaml"
        real_target = tmp_path / "outside-target.yaml"
        real_target.write_text("x: 1\n", encoding="utf-8")
        target_file.unlink()
        target_file.symlink_to(real_target)

        exit_code = tool.run(
            [
                "--source",
                str(source),
                "--release",
                VALID_RELEASE,
                "--commit",
                VALID_COMMIT,
                "--dest",
                str(tmp_path / "dest"),
            ]
        )
        assert exit_code == 1
