# Vendored `basis-schemas` v0.2.1 operation-aware snapshot

This directory is a pinned, immutable copy of a narrow subset of
[`basis-schemas`](https://github.com/basis-foundation/basis-schemas) at
release tag `v0.2.1` (commit `945acd107016bcbcb114f440474df204ead3f8f3`):
the 14 operation-aware contract schemas and the 5 canonical
compatibility-vector scenarios. It exists so that `basis-core`'s test suite
is reproducible, runs offline, and does not depend on GitHub or PyPI
availability during development, review, or CI.

This is the sibling snapshot to `tests/fixtures/basis-schemas/v0.2.0/`
(unchanged, immutable, retained). See that directory's own `README.md` for
the full ownership, authority, kernel/gateway-boundary, inert-placeholder,
and refresh-procedure documentation — it applies here unchanged. This file
covers only what is specific to `v0.2.1`.

## What changed from `v0.2.0`

`v0.2.1` corrects a single upstream defect in the `invalid-policy-bundle`
compatibility scenario. In `v0.2.0`, the scenario's four kernel/gateway
result artifacts (`expected-evaluation-trace.yaml`,
`expected-operation-aware-decision-response.yaml`,
`expected-audit-evidence.yaml`, `expected-gateway-audit-event.yaml`) used
`failure_reason: invalid_policy_bundle` and, on three of the four,
`reason_code: policy_bundle_invalid`. Both values were wrong for what the
fixture actually demonstrates: a bundle that is *shaped correctly* per the
`policy-bundle` contract but fails a cross-rule, bundle-level consistency
invariant (`rule_id` values must be unique across a bundle's `rules`
array). `invalid_policy_bundle` denotes a shape/schema-conformance failure,
which this fixture is not.

`v0.2.1` corrects this to `failure_reason: policy_validation_failure` in
all four artifacts, and removes `reason_code: policy_bundle_invalid`
outright rather than substituting a different reason code — no approved
reason-code equivalent for this semantic-validation category is published
in `basis-schemas`' governed reason-code vocabulary, so none is invented
here or upstream.

The scenario's defect itself is unchanged: `invalid-policy-bundle.yaml`
still declares two rules sharing `rule_id: allow-duplicate-rule` (only its
explanatory comment was reworded upstream to describe the corrected
category). `evaluation_status: failed`, `outcome: null`, and the gateway's
`enforcement_action: deny` are unchanged. The other four scenarios
(`allow-basic`, `deny-precedence`, `default-deny`, `not-applicable`) and
all 14 schema contracts are byte-identical to `v0.2.0` — confirmed by
comparing this directory's `manifest.json` against `v0.2.0/manifest.json`
entry by entry.

No `basis-core` evaluator behavior changes as a result of this refresh.
This directory remains test/development input only, exactly as described
in `v0.2.0/README.md`'s "Ownership and authority" section.

## Provenance and integrity

`manifest.json` in this directory records the same fields as `v0.2.0`'s:
`source_repository`, `source_release` (`v0.2.1`), `source_commit`
(`945acd107016bcbcb114f440474df204ead3f8f3`), `captured_at`
(`2026-07-19T02:18:38Z`), and `files` (every vendored file's path mapped to
its SHA-256 digest). `tests/test_basis_schemas_snapshot_integrity.py` and
`tests/test_basis_schemas_snapshot_provenance.py` verify this snapshot the
same way they verify `v0.2.0`'s (now pointed at `v0.2.1` as the active
snapshot — see `tests/helpers/basis_schemas_snapshot.py`'s
`SNAPSHOT_RELEASE`).

**A note on the `captured_at` field name.** Despite the name, this is
*not* the wall-clock time this refresh happened to run — it is the
`v0.2.1` tag commit's own committer date, converted to UTC. This is the
same convention `v0.2.0/README.md`'s "Provenance and integrity" section
documents: "`captured_at` — the source commit's own committer date (UTC),
not the wall-clock time the refresh happened to run, so re-running the
refresh against the same commit reproduces an identical manifest." The
field name is a slight misnomer for what it actually holds, but the
behavior is deliberate — `scripts/update_basis_schemas_snapshot.py`'s
`resolve_captured_at()` derives it from `git log -1 --format=%cI` against
the source tree by default, precisely so re-vendoring the same commit
twice reproduces byte-identical output. This snapshot's value was computed
the same way (from a `git log -1 --format=%cI` read against the tag commit
in a local `basis-schemas` clone, since a `git archive` extract has no
`.git` directory for the tool to read directly) and passed explicitly via
`--captured-at`. The manifest format itself is unchanged; only this note
is new.

## Consuming this snapshot in tests

Use `tests/helpers/basis_schemas_snapshot.py`, not raw path construction —
see `v0.2.0/README.md`'s "Consuming this snapshot in tests" section for the
unchanged usage example. `SNAPSHOT_RELEASE` in that module now points at
`v0.2.1`; `v0.2.0` remains on disk, addressable directly by path, for
historical reference.
