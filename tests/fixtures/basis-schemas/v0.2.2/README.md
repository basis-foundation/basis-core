# Vendored `basis-schemas` v0.2.2 operation-aware snapshot

This directory is a pinned, immutable copy of a narrow subset of
[`basis-schemas`](https://github.com/basis-foundation/basis-schemas) at
release tag `v0.2.2` (commit `da7832972dad36dea6ef2796161a1990fbbe6a05`):
the 14 operation-aware contract schemas and the 5 canonical
compatibility-vector scenarios. It exists so that `basis-core`'s test suite
is reproducible, runs offline, and does not depend on GitHub or PyPI
availability during development, review, or CI.

This is the sibling snapshot to `tests/fixtures/basis-schemas/v0.2.0/` and
`tests/fixtures/basis-schemas/v0.2.1/` (both unchanged, immutable,
retained). See `v0.2.0/README.md` for the full ownership, authority,
kernel/gateway-boundary, inert-placeholder, and refresh-procedure
documentation — it applies here unchanged. This file covers only what is
specific to `v0.2.2`.

## What changed from `v0.2.1`

`v0.2.2` corrects three evidence-provenance disagreements that canonical
conformance work against `v0.2.1` surfaced between this repository's
merged implementation and the vendored fixtures. `basis-architecture`
settled the governing semantics for all three (see
`docs/architecture/operation-aware-evidence-provenance-semantics.md`), and
`basis-schemas` v0.2.2 publishes the corrected canonical artifacts
reflecting that resolution:

1. **No synthesized top-level explanation.** `basis-core` does not
   synthesize aggregate, human-readable prose merely to populate an
   `explanation` field. `OperationAwareDecisionResponse.explanation`,
   `EvaluationTrace.explanation`, and `AuditEvidence.explanation` remain
   `null` whenever no governed stage supplies one — that `null` is the
   correct, complete value, not a defect. `reason_code` remains the
   authoritative machine-readable explanation. `v0.2.1`'s fixtures
   incorrectly expected synthesized top-level prose in several scenarios;
   `v0.2.2` corrects every top-level `explanation` field across all five
   scenarios' result artifacts to `null`.

2. **Per-rule authored rationale follows `rule_result`.** A `matched`
   rule's authored `reason_code`/`explanation` are preserved verbatim
   (including a matched-but-non-decisive rule under deny precedence, e.g.
   `deny-precedence`'s `allow-operator-write-hvac-setpoint`); a
   `not_matched` or `skipped` rule's are omitted entirely (`null`); an
   `error` rule's are never the rule's authored allow/deny rationale.
   `v0.2.1` projected this inconsistently. `v0.2.2` also corrects the
   authored wording on `deny-precedence`'s denying rule from an incorrect
   singular form to `"Control-affecting operations are denied while an
   interlock is engaged."` (plural "operations").

3. **Bundle identity is retained as provenance, not proof of
   applicability.** `bundle_id`/`bundle_version` are preserved whenever a
   trustworthy typed `PolicyBundle` exists for the evaluation — including
   completed `NOT_APPLICABLE` evaluations (`not-applicable`:
   `bundle-compat-hvac-scope` / `1.0.0`) and typed semantic
   policy-validation failures (`invalid-policy-bundle`:
   `bundle-compat-invalid-policy` / `1.0.0`) — independent of whether the
   bundle applied, matched, or passed validation. `v0.2.1` omitted bundle
   identity from these two scenarios' result artifacts; `v0.2.2` restores
   it.

These corrections touch only the 20 `expected-*.yaml` **result** artifacts
across all five scenarios (`expected-evaluation-trace.yaml`,
`expected-operation-aware-decision-response.yaml`,
`expected-audit-evidence.yaml`, `expected-gateway-audit-event.yaml`). The
input artifacts — every `operation-aware-decision-request.yaml`,
`policy-bundle.yaml`, and `invalid-policy-bundle.yaml` — and all 14 schema
contracts are byte-identical to `v0.2.1` (and, in turn, to `v0.2.0`) —
confirmed by comparing this directory's `manifest.json` against
`v0.2.1/manifest.json` entry by entry. `invalid-policy-bundle.yaml` still
declares two rules sharing `rule_id: allow-duplicate-rule`; the scenario's
underlying defect and its `failure_reason: policy_validation_failure`
classification (corrected in `v0.2.1`) are unchanged.

No `basis-core` evaluator behavior changes as a result of vendoring this
snapshot. This directory remains test/development input only, exactly as
described in `v0.2.0/README.md`'s "Ownership and authority" section. The
corresponding `basis-core` implementation correction (per-rule rationale
projection by `RuleResult`) landed on `main` ahead of this vendoring PR,
in `evaluation/operation_aware/trace_assembly.py`'s
`assemble_rule_evidence`/`_project_rule_rationale`.

## Provenance and integrity

`manifest.json` in this directory records the same fields as
`v0.2.0`'s and `v0.2.1`'s: `source_repository`, `source_release`
(`v0.2.2`), `source_commit`
(`da7832972dad36dea6ef2796161a1990fbbe6a05`), `captured_at`
(`2026-07-23T02:06:25Z`), and `files` (every vendored file's path mapped
to its SHA-256 digest). `tests/test_basis_schemas_snapshot_integrity.py`
and `tests/test_basis_schemas_snapshot_provenance.py` verify this snapshot
the same way they verify `v0.2.0`'s and `v0.2.1`'s (now pointed at
`v0.2.2` as the active snapshot — see
`tests/helpers/basis_schemas_snapshot.py`'s `SNAPSHOT_RELEASE`).

As with `v0.2.1`, `captured_at` is not the wall-clock time this refresh
happened to run — it is the `v0.2.2` tag commit's own committer date,
converted to UTC, derived by `scripts/update_basis_schemas_snapshot.py`'s
`resolve_captured_at()` reading `git log -1 --format=%cI` against a local
`basis-schemas` clone checked out at the `v0.2.2` tag. Re-vendoring the
same commit reproduces an identical manifest.

## Consuming this snapshot in tests

Use `tests/helpers/basis_schemas_snapshot.py`, not raw path construction —
see `v0.2.0/README.md`'s "Consuming this snapshot in tests" section for the
unchanged usage example. `SNAPSHOT_RELEASE` in that module now points at
`v0.2.2`; `v0.2.0` and `v0.2.1` remain on disk, addressable directly by
path, for historical reference.
