# Changelog

All notable changes to `basis-core` are recorded here. The format is loosely
based on [Keep a Changelog](https://keepachangelog.com/); breaking vs.
additive classification follows `docs/breaking-change-discipline.md`.

## [Unreleased]

### Added

- **Operation-aware evidence-reference models.** Adds
  `src/basis_core/domain/evidence.py` — the second production module added
  under `src/basis_core/` for `basis-core` v0.2.0 (Milestone 2, PR 6 of
  `docs/implementation/basis-core-v0.2-operation-aware-plan.md`). Implements
  immutable identity and adapter evidence-reference models —
  `IdentityEvidenceReference` and `AdapterEvidenceReference` — for the
  operation-aware authorization surface, matching the
  `identity-evidence-reference` and `adapter-evidence-reference` contracts
  published by `basis-schemas` v0.2.0, plus an internal `EvidenceDigest`
  value object for their shared digest shape. Both models are frozen
  Pydantic models (`extra="forbid"`, matching the existing `Subject`/
  `Resource`/`AuditEvent` convention), reuse PR 5's `RedactionClassification`,
  and validate reference identifiers, evidence-source labels, digest
  algorithm/value patterns, and (for adapter references) an open,
  protocol-neutral `protocol` label — all taken directly from the vendored
  contract fixtures.

  **Evidence references remain structurally bounded — they are not evidence
  trust.** Neither model has a field capable of holding a raw access token,
  ID token, refresh token, JWT, bearer token, authorization header, cookie,
  session secret, client secret, password, private key, raw claim set, or
  raw protocol payload, and both reject unknown fields at construction. No
  digest verification, signature verification, evidence retrieval,
  evidence-provenance authentication, or trust-establishment behavior is
  implemented or implied — `EvidenceDigest` carries a structurally
  well-formed algorithm label and hex value only, never a claim that the
  digest is authentic. This PR does **not** implement
  `OperationAwareDecisionRequest`, context value objects, any policy or
  condition model, or any evaluator behavior — those remain later,
  separately-scoped roadmap PRs (Milestone 2, PR 7 onward). Neither model is
  yet re-exported from `basis_core.domain` or listed in
  `docs/public-api.md`'s stable public API table; per the roadmap's default
  position, operation-aware symbols are added internally first and graduate
  to the public API in a later, dedicated milestone (Milestone 11, PR 35).

  Adds `tests/operation_aware/test_evidence.py` (schema-alignment,
  valid/invalid construction cross-checked against every vendored
  `identity-evidence-reference`/`adapter-evidence-reference` example,
  immutability, equality, hashing, and dedicated security/data-minimization
  coverage rejecting raw-evidence-shaped fields) and
  `tests/operation_aware/test_evidence_boundaries.py` (import-boundary and
  public-API-surface checks specific to the new module). 113 new tests
  (1053 total, up from 940 after PR 5); all 4 quality gates green. No
  existing v0.1.0 behavior, model, or public API changed.

- **Operation-aware shared vocabulary value objects.** Adds
  `src/basis_core/domain/operation_aware_vocabulary.py` — the first
  production module added under `src/basis_core/` for `basis-core` v0.2.0
  (Milestone 2, PR 5 of
  `docs/implementation/basis-core-v0.2-operation-aware-plan.md`). Implements
  `RedactionClassification` (a closed, five-value `str, Enum` — `safe_to_expose`,
  `safe_after_redaction`, `reference_only`, `never_store`, `never_display` —
  matching the `redaction-classification` contract published by
  `basis-schemas` v0.2.0) and `ReasonCode` (a validated, open-format `str`
  subclass — lowercase snake_case, non-empty, matching the `reason-code`
  contract's published pattern; deliberately not a closed enum, per that
  contract). Both types are immutable, have deterministic equality,
  hashing, and representation, perform explicit validation with no silent
  coercion, and depend only on the Python standard library (`re`, `enum`) —
  no YAML, no new runtime dependency, no protocol/adapter/identity-provider
  dependency.

  This PR does **not** implement `OperationAwareDecisionRequest`,
  evidence-reference models, context value objects, any policy or condition
  model, or any evaluator behavior — those remain later, separately-scoped
  roadmap PRs (Milestone 2, PR 6 onward). Neither type is yet re-exported
  from `basis_core.domain` or listed in `docs/public-api.md`'s stable
  public API table; per the roadmap's default position, operation-aware
  symbols are added internally first and graduate to the public API in a
  later, dedicated milestone (Milestone 11, PR 35).

  Adds `tests/operation_aware/test_vocabulary.py` (enum exhaustiveness,
  valid/invalid construction cross-checked against every vendored
  `redaction-classification`/`reason-code` example, immutability, equality,
  hashing, deterministic representation) and
  `tests/operation_aware/test_vocabulary_boundaries.py` (import-boundary
  and public-API-surface checks specific to the new module). 78 new tests
  (940 total, up from 862 after PR 4); all 4 quality gates green. No
  existing v0.1.0 behavior, model, or public API changed.

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
