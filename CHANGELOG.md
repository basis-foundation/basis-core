# Changelog

All notable changes to `basis-core` are recorded here. The format is loosely
based on [Keep a Changelog](https://keepachangelog.com/); breaking vs.
additive classification follows `docs/breaking-change-discipline.md`.

## [Unreleased]

### Added

- **Safe operation-aware YAML contract loading and generic structural
  validation.** Adds `tests/helpers/operation_aware_contracts.py`,
  completing the remaining scope of Milestone 1, PR 4
  (`docs/implementation/basis-core-v0.2-operation-aware-plan.md`): a
  test-only YAML loader (`load_yaml_document`, `yaml.SafeLoader`-based with
  an added duplicate-mapping-key rejection, no unsafe tag construction, no
  multi-document input, no empty documents), snapshot-boundary-aware
  wrappers (`load_contract`, `load_scenario_artifact`) built on PR 2's
  existing discovery helpers, a concise test-helper exception hierarchy
  distinguishing missing file / unsafe path / invalid YAML / empty document
  / multi-document / unexpected root type, generic structural-validation
  helpers (`require_mapping`, `require_sequence`, `require_string_field`,
  `require_mapping_field`, `require_sequence_field`, `require_optional_field`,
  `reject_unknown_fields`), and `validate_contract_metadata`, which checks
  only the structural presence and type of the shared `contract:` metadata
  block (`contract`, `.name`, `.version`, `.lifecycle`, `.depends_on`) —
  never its patterns, enums, or any other business rule the
  `contract-metadata` contract itself already governs.

  Adds `tests/operation_aware/test_contract_loading.py` (all 14 pinned
  contracts parse, have mapping roots, structurally valid metadata, a
  `name` matching their own inventory entry, deterministic repeated loads,
  and no mutation by validation helpers),
  `tests/operation_aware/test_compatibility_fixture_loading.py` (all 5
  pinned scenarios' artifacts parse and have mapping roots, artifact
  discovery matches the existing helper inventory, and the gateway-only
  artifact still loads while remaining labeled reference-only), and
  `tests/operation_aware/test_yaml_loader_negative.py` (16 negative cases
  against temporary files outside the pinned snapshot: missing path,
  directory-as-file, empty/whitespace/explicit-null documents, malformed
  YAML, multi-document YAML, an unsafe `!!python/object/apply` tag,
  duplicate mapping keys, invalid UTF-8, an unexpected scalar root, and
  absolute/`..`-traversal/symlink boundary escapes). Extends
  `tests/test_basis_schemas_snapshot_boundaries.py` with a check that no
  `src/basis_core/` file imports `yaml`.

  Adds `PyYAML>=6.0` to `pyproject.toml`'s
  `[project.optional-dependencies].dev` — test/development-only, never a
  runtime dependency. This is test infrastructure only: no
  `src/basis_core/` change, no operation-aware domain model, no semantic
  policy or request validation, no public API change. Milestone 0 and
  Milestone 1 of
  `docs/implementation/basis-core-v0.2-operation-aware-plan.md` are now
  both complete.

- **Pinned `basis-schemas` v0.2.0 operation-aware test snapshot.** Vendors a
  narrowly-scoped, immutable copy of the 14 operation-aware contract schemas
  and the 5 canonical compatibility-vector scenarios published by
  `basis-schemas` release `v0.2.0` (commit
  `1d3af3cfd38686173980cfb47f8fa44659a4e1c4`) into
  `tests/fixtures/basis-schemas/v0.2.0/`, together with a `manifest.json`
  recording per-file SHA-256 digests and exact source provenance
  (`source_repository`, `source_release`, `source_commit`). Adds
  `tests/helpers/basis_schemas_snapshot.py` (test-only discovery helpers:
  `get_schema_path`, `get_scenario_artifact`,
  `list_operation_aware_contracts`, `list_compatibility_scenarios`,
  `load_snapshot_manifest`) and `scripts/update_basis_schemas_snapshot.py`
  (a network-free, deterministic refresh tool that copies a fixed, reviewed
  allowlist of files from a local `basis-schemas` checkout and regenerates
  the manifest). Adds inventory, integrity, provenance, refresh-tool, and
  scope-boundary tests
  (`tests/test_basis_schemas_snapshot*.py`,
  `tests/test_update_basis_schemas_snapshot.py`).

  This is test and development infrastructure only: `basis-schemas` is not
  added as a runtime or dev dependency, the snapshot is not exposed through
  any `basis_core` public export, and no operation-aware domain model,
  evaluator, request/response type, or evaluation semantics are implemented
  by this change. It exists so that future operation-aware implementation
  work has a reproducible, offline, immutable target to build and test
  against, per
  `docs/implementation/basis-core-v0.2-operation-aware-plan.md` Section 4.
  See `tests/fixtures/basis-schemas/v0.2.0/README.md` for ownership and
  refresh documentation, and `docs/compatibility-testing.md` for how this
  harness relates to the existing v0.1.0 compatibility-testing harness.

- **Operation-aware test package scaffold.** Adds `tests/operation_aware/`
  (`__init__.py`, `README.md`, `test_scaffold.py`) as the dedicated test
  package that future operation-aware model, policy, trace, audit, and
  evaluator tests will use. Proves that pytest discovers and runs tests in
  the new subpackage and that it can reach the pinned `basis-schemas`
  v0.2.0 fixture snapshot through the existing
  `tests/helpers/basis_schemas_snapshot.py` helper. No production code, no
  YAML parsing, no new dependencies, and no public API changes are included
  — this is test-infrastructure only, per
  `docs/implementation/basis-core-v0.2-operation-aware-plan.md` Milestone 0,
  PR 3.

## [0.1.0] - 2026-05-27

Initial public release. See `docs/v0.1-readiness-review.md` and
`docs/public-api.md` for the stabilized v0.1.0 surface.
