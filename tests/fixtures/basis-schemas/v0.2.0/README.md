# Vendored `basis-schemas` v0.2.0 operation-aware snapshot

This directory is a pinned, immutable copy of a narrow subset of
[`basis-schemas`](https://github.com/basis-foundation/basis-schemas) at
release tag `v0.2.0` (commit `1d3af3cfd38686173980cfb47f8fa44659a4e1c4`):
the 14 operation-aware contract schemas and the 5 canonical
compatibility-vector scenarios. It exists so that `basis-core`'s test suite
is reproducible, runs offline, and does not depend on GitHub or PyPI
availability during development, review, or CI.

## Ownership and authority

`basis-schemas` remains the single source of truth for these contracts.
Nothing in this directory is authored by `basis-core`, and nothing here
changes, reinterprets, or extends what `basis-schemas` published. This
directory is:

- **test and development input only** — read by test code under `tests/`,
  never by `src/basis_core/`.
- **not a runtime dependency** — `basis-schemas` is not, and will not become,
  a `pyproject.toml` dependency because of this directory.
- **not a new schema authority** — if a schema here and the live
  `basis-schemas` repository ever disagree, `basis-schemas` is correct and
  this snapshot is stale; that is a signal to refresh it (see below), not to
  hand-edit it into agreement.
- **not a fork of `basis-schemas`** — no file here is modified from its
  source form. Every vendored file's SHA-256 digest is recorded in
  `manifest.json` and verified by
  `tests/test_basis_schemas_snapshot_integrity.py`.
- **not editable by hand** — a refresh is always a full-directory
  replacement produced by `scripts/update_basis_schemas_snapshot.py`, never
  a manual patch. A hand edit would silently desynchronize the file from its
  recorded SHA-256 digest, which the integrity tests would then catch and
  fail on — that failure is the intended detection mechanism, not a bug.
- **not part of the `basis_core` public API** — nothing under
  `src/basis_core/` imports from this directory, and it is not packaged into
  the built wheel (`tool.hatch.build.targets.wheel.packages` includes only
  `src/basis_core`).

## What is vendored, and what is not

`schemas/` contains the 14 operation-aware contract YAML files (shared
metadata and vocabulary, evidence references, the operation-aware decision
request, the policy bundle/rule/condition model, the response/trace model,
and the audit model). The six first-wave contracts that already mirror
`basis-core` v0.1.0 unchanged (`vocabulary`, `action-string`,
`resource-identifier`, `decision-request`, `decision-response`,
`audit-event`) are deliberately **not** vendored here — they are out of
scope for the operation-aware snapshot.

`compatibility/` contains the five canonical compatibility scenarios
published by `basis-schemas` PR G
(`examples/operation-aware/compatibility/` upstream): `allow-basic`,
`deny-precedence`, `default-deny`, `not-applicable`, and
`invalid-policy-bundle`. Each scenario directory carries six artifacts,
copied verbatim.

## Kernel-owned vs. gateway-only artifacts

Per scenario, five artifacts are kernel-boundary artifacts — inputs to, or
expected outputs of, a `basis-core` evaluator:

- `operation-aware-decision-request.yaml` — the request (kernel input)
- `policy-bundle.yaml` (or, for `invalid-policy-bundle`,
  `invalid-policy-bundle.yaml`) — the policy bundle (kernel input)
- `expected-evaluation-trace.yaml` — the expected evaluation trace (kernel
  output)
- `expected-operation-aware-decision-response.yaml` — the expected response
  (kernel output)
- `expected-audit-evidence.yaml` — the expected audit evidence (kernel
  output)

The sixth artifact, `expected-gateway-audit-event.yaml`, is retained as
**cross-boundary reference data only**. `basis-core` does not produce,
consume, or own `GatewayAuditEvent` records — that is `basis-gateway`'s
responsibility, assembled from a kernel response/trace plus the audit
evidence. Tests in this repository must never treat
`expected-gateway-audit-event.yaml` as a kernel-expected output; see
`tests/helpers/basis_schemas_snapshot.py`'s `KERNEL_SCENARIO_ARTIFACTS` /
`GATEWAY_ONLY_SCENARIO_ARTIFACTS` split, which encodes this distinction
programmatically.

## Inert placeholder data

A small number of the vendored contract YAMLs (`audit-evidence`,
`operation-aware-decision-response`, `operation-aware-decision-request`,
`identity-evidence-reference`, `policy-bundle`) carry their own upstream
`examples:` blocks that deliberately illustrate a **rejected**, invalid
shape — for instance a `private_key` or `access_token` field, to show that
the contract's `additionalProperties: false` policy rejects it. These
values (e.g. `eyJhbGciOiJSUzI1NiJ9.example.signature`,
`-----BEGIN PRIVATE KEY-----example-----END PRIVATE KEY-----`) are
upstream-authored, inert, syntactically-fake placeholder strings, not real
credentials, and were reviewed as part of vendoring this snapshot. See
`examples/operation-aware/compatibility/README.md` §16 in `basis-schemas`
("Security and synthetic-data policy") for the same policy applied to the
canonical compatibility vectors: every identifier, digest, and timestamp in
`compatibility/` is synthetic and deterministic.

## Schema publication vs. runtime implementation

This snapshot publishes machine-readable *shapes* and worked examples. It
does not implement, approximate, or stand in for `basis-core` evaluation
behavior. No policy bundle is parsed, no condition is evaluated, no
selector is matched, and no response is produced by anything in this
directory or by the test-fixture helpers that read it. That implementation
work is later, separate `basis-core` v0.2.0 roadmap work (see
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`).

## Provenance and integrity

`manifest.json` in this directory records:

- `source_repository` — `basis-foundation/basis-schemas`
- `source_release` — `v0.2.0`
- `source_commit` — the exact 40-character tagged commit SHA
- `captured_at` — the source commit's own committer date (UTC), not the
  wall-clock time the refresh happened to run, so re-running the refresh
  against the same commit reproduces an identical manifest
- `files` — every vendored file's path (relative to this directory) mapped
  to its SHA-256 digest

`tests/test_basis_schemas_snapshot_integrity.py` recomputes and checks every
digest, rejects unmanifested files, rejects manifest entries whose file no
longer exists, rejects absolute paths and `..` traversal, and rejects
symlinks. `tests/test_basis_schemas_snapshot_provenance.py` asserts the
`source_repository` / `source_release` / `source_commit` values above
exactly, not merely that they are non-empty.

## Refreshing this snapshot

Refreshing is always a full-directory replacement, performed by an explicit,
reviewed pull request — never a partial hand edit. The tool never touches
the network; it requires a local, already-checked-out `basis-schemas` tree
at the target release.

```bash
# 1. Obtain a local, pristine checkout of the target basis-schemas release
#    (never fetched by the tool below — this step is a human/CI step that
#    uses your own git/network access, outside this repository).
git clone https://github.com/basis-foundation/basis-schemas /tmp/basis-schemas
git -C /tmp/basis-schemas archive v0.3.0 | tar -x -C /tmp/basis-schemas-v0.3.0

# 2. Run the refresh tool from the basis-core repository root.
python scripts/update_basis_schemas_snapshot.py \
    --source /tmp/basis-schemas-v0.3.0 \
    --release v0.3.0 \
    --commit <exact tagged commit SHA>

# 3. Review the diff. A meaningful upstream contract change produces a
#    visible, reviewable diff here, exactly like a dependency version bump.
#    Run the full test suite; downstream operation-aware conformance tests
#    (once implemented) will confirm whether the refreshed contracts still
#    produce the same canonical-vector outcomes.
pytest
```

The refresh tool (`scripts/update_basis_schemas_snapshot.py`) verifies the
declared `--release` against the source tree's own `pyproject.toml` (and,
if present, `src/basis_schemas/__init__.py`) before copying anything, copies
only the fixed, reviewed allowlist of contract and scenario files it knows
about, rejects the run outright if any expected file is missing or any
unexpected contract/scenario directory is present, and regenerates
`manifest.json` deterministically. Updating what the tool considers
"expected" (e.g. adding a 15th operation-aware contract in a future
`basis-schemas` release) is itself a reviewed source change to the script,
not a runtime flag.

## Consuming this snapshot in tests

Use `tests/helpers/basis_schemas_snapshot.py`, not raw path construction:

```python
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
```

This PR provides discovery and integrity helpers only — no YAML parsing, no
schema-to-model conversion, and no operation-aware domain models. Those are
later, separate roadmap PRs.
