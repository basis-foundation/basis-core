# Changelog

Notable changes to `basis-core` are documented here. The format is loosely
based on [Keep a Changelog](https://keepachangelog.com/); breaking vs.
additive classification follows `docs/breaking-change-discipline.md`.

## [0.2.0]

### Added

- The operation-aware request surface: `OperationAwareDecisionRequest` and
  its six OT context objects (location, device, protocol, safety,
  environment, risk).
- Bounded identity and adapter evidence references
  (`IdentityEvidenceReference`, `AdapterEvidenceReference`) and the shared
  operation-aware vocabulary (`RedactionClassification`, `ReasonCode`,
  `EvidenceDigest`).
- The structured policy data model: `PolicyBundle`, `PolicyBundleScope`,
  `OperationAwarePolicyRule`, `OperationAwarePolicyMatch`, and
  `PolicyCondition`, including the approved, closed, ten-operator
  deterministic condition registry (`equals`, `not_equals`, `in`, `not_in`,
  `greater_than`, `greater_than_or_equal`, `less_than`,
  `less_than_or_equal`, `exists`, `not_exists`).
- The deterministic operation-aware evaluation pipeline: policy validation,
  bundle applicability, rule-selector matching, condition evaluation, and
  effect aggregation, with enforced deny precedence, default deny, and a
  `NOT_APPLICABLE` outcome kept distinct from both.
- A deterministic `EvaluationTrace` and a bounded `AuditEvidence` artifact,
  each produced separately from the decision response.
- `OperationAwareEnforcementPoint`, a separate enforcement boundary from the
  v0.1 `EnforcementPoint`, with fail-closed enforcement-disposition mapping.
- Public API exports for the operation-aware surface across `domain`,
  `decisions`, `policy`, `audit`, and `enforcement`.
- Canonical conformance against the vendored `basis-schemas` `v0.2.2`
  snapshot (five canonical scenarios).
- Implementation, compatibility, governance, and readiness documentation:
  `docs/implementation/basis-core-v0.2-operation-aware-plan.md`,
  `docs/operation-aware-model.md`,
  `docs/operation-aware-evaluation-semantics.md`,
  `docs/schema-versioning.md`'s and `docs/breaking-change-discipline.md`'s
  operation-aware sections, and `docs/v0.2-readiness-review.md`.

### Compatibility

- The v0.1 public surface remains supported. `DecisionRequest`,
  `DecisionResponse`, `AuditEvent`, `PolicyRule`, `EnforcementPoint`, and the
  `AdapterBase`/`AuditWriter` extension contracts are unchanged.
- The operation-aware APIs are additive siblings to the v0.1 surface, not a
  replacement for it. `OperationAwarePolicyRule` does not replace the v0.1
  `PolicyRule` Protocol — both remain independently exported from
  `basis_core.policy`.
- No migration from v0.1 is required. Existing v0.1 integrations continue
  to work unmodified.
- Historical v0.1 fixtures and contract snapshots remain byte-exact.

### Architecture and boundaries

- `basis-core` remains deterministic and synchronous; no asynchronous or
  I/O-bound evaluation path was introduced.
- No authentication, token verification, or identity-provider call was
  added.
- No field-protocol communication was added.
- No persistence layer was added.
- No `basis-gateway` behavior was added to this repository.
- `GatewayAuditEvent` remains outside kernel ownership; `basis-core` does
  not construct it.
- `AuditEvidence` is produced by the kernel but is not persisted by it —
  persistence is the consuming application's responsibility.
- `basis-schemas` remains a test-time conformance input, copied into
  vendored fixtures for canonical-scenario testing; it is not a runtime
  dependency of `basis-core`.

### Validation

- All five canonical scenarios (`allow-basic`, `deny-precedence`,
  `default-deny`, `not-applicable`, `invalid-policy-bundle`) pass through
  the real `OperationAwareEnforcementPoint.evaluate()` path against the
  vendored `basis-schemas` `v0.2.2` snapshot (16/16 assertions).
- v0.1 backward-compatibility, contract-snapshot, schema-versioning, and
  import-boundary checks pass unmodified (247 passed).
- The full operation-aware suite passes (3098 passed, 86 skipped) and the
  full repository test suite passes (3953 passed, 86 skipped, including
  this release's own version-synchronization and changelog readiness
  checks).
- `ruff check`, `ruff format --check`, and `mypy --strict` all pass clean.

## [0.1.0] - 2026-05-27

Initial public release. See `docs/v0.1-readiness-review.md` and
`docs/public-api.md` for the stabilized v0.1.0 surface.
