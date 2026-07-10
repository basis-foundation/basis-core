# Changelog

All notable changes to `basis-core` are recorded here. The format is loosely
based on [Keep a Changelog](https://keepachangelog.com/); breaking vs.
additive classification follows `docs/breaking-change-discipline.md`.

## [Unreleased]

### Added

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

## [0.1.0] - 2026-05-27

Initial public release. See `docs/v0.1-readiness-review.md` and
`docs/public-api.md` for the stabilized v0.1.0 surface.
