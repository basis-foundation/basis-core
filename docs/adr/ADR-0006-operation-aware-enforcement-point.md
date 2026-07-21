# ADR-0006 — Operation-Aware Enforcement Point Design Decision

**Status**: Accepted
**Date**: 2026-07-20

## Context

This is `basis-core` v0.2.0 roadmap Milestone 11, PR 33
(`docs/implementation/basis-core-v0.2-operation-aware-plan.md`). It is a
docs-only design-decision record. It implements no code. Its purpose is to
remove the remaining ambiguity around the operation-aware enforcement
contract so PR 34 can implement `OperationAwareEnforcementPoint` without
inventing architecture.

### v0.1.0 `EnforcementPoint` — current guarantees (unchanged by this ADR)

`basis_core.enforcement.enforcement.EnforcementPoint`
(`src/basis_core/enforcement/enforcement.py`) is constructed with:

```text
EnforcementPoint(
    engine: PolicyEngine,
    audit_writer: AuditWriter,
    policy_version: str | None = None,
)
```

Its sole public method:

```text
evaluate(
    request: DecisionRequest | dict[str, object],
    subject: Subject | None = None,
    identity_context: IdentityContext | None = None,
    correlation_id: str | None = None,
) -> DecisionResponse
```

Guarantees, inspected directly from the current merged implementation:

- **Accepted input forms**: a validated `DecisionRequest`, or a raw
  `dict[str, object]` that is validated into one via
  `DecisionRequest.model_validate`. A dict that fails validation never
  reaches policy evaluation.
- **Configured dependencies**: exactly a `PolicyEngine` and an
  `AuditWriter`, supplied once at construction. Neither is optional; there
  is no policy-loading, no file/environment/network policy source inside
  `EnforcementPoint` itself.
- **Fail-closed behavior**: every failure path returns
  `DecisionResponse(outcome=DecisionOutcome.DENY, ...)` with one of three
  `FailureReason` values — `MALFORMED_REQUEST` (dict validation failure or
  `Subject` construction failure), `POLICY_ERROR` (an exception raised
  inside `PolicyEngine.evaluate()`, or `Decision.is_error=True` returned by
  it), `INTERNAL_ERROR` (an outer catch-all for any other unexpected
  exception). `NOT_APPLICABLE` from the policy engine is mapped straight
  through as `DecisionOutcome.NOT_APPLICABLE` (not `DENY`) at this layer —
  the v0.1 default-deny-at-enforcement collapse happens one layer up, in
  `_DECISION_OUTCOME_TO_AUDIT_OUTCOME` for audit purposes only, not in the
  returned `DecisionResponse.outcome` itself.
- **Exception containment**: `evaluate()` never raises. The method body is
  wrapped so that a validation failure, a subject-construction failure, a
  policy-engine exception, or any other unexpected exception each produce a
  `DecisionResponse` rather than propagate. Raw exception text is logged
  (`log.exception` / `log.warning`) but never placed in `response.reason`;
  callers see only the three static, safe reason strings
  (`_REASON_MALFORMED`, `_REASON_POLICY_ERROR`, `_REASON_INTERNAL`).
- **Response construction**: `DecisionResponse` fields
  (`request_id`, `outcome`, `reason`, `evaluated_by`, `policy_version`,
  `failure_reason`, `timestamp`) are constructed once per call, from the
  validated request and the engine's `Decision`, through normal Pydantic
  validation.
- **Audit writing**: `_write_audit()` is called on every reachable path
  except the dict-validation-failure path (no valid `action`/`resource_id`
  exists yet to build an `AuditEvent` from). It builds a `DecisionTrace`
  from `Decision.evaluated_rules` when available, maps the outcome to
  `AuditOutcome`, and calls `AuditWriter.write()`. `_write_audit()` itself
  is wrapped in `try/except Exception`: a write failure is logged and
  swallowed; it never reverses or mutates the already-returned
  `DecisionResponse`, and `evaluate()` returns the response regardless of
  whether the audit write succeeded.
- **Public import paths**: `EnforcementPoint` is the sole export of
  `basis_core.enforcement` (`__all__ = ["EnforcementPoint"]`,
  `src/basis_core/enforcement/__init__.py`), documented in
  `docs/public-api.md` as the stable public API entry.
- **Extension-contract commitments**
  (`docs/extension-contracts.md`, "EnforcementPoint orchestration
  expectations"): `EnforcementPoint` is the only component authorized to
  call both `PolicyEngine` and `AuditWriter` in the same execution path;
  extensions must not replicate that orchestration, call
  `EnforcementPoint.evaluate()` recursively, or call `AuditWriter.write()`
  directly from a policy rule. `docs/kernel-constitution.md` Invariant 6
  ("Enforcement fails closed") and Invariant 1 ("The kernel is isolated")
  govern this behavior and are unchanged by anything in this ADR.

### Operation-aware evaluation and assembly — current merged surface

Inspected directly from the currently merged code on `main` (PRs 24–32,
`git log --oneline`, tip `69f15c0`), not from historical roadmap sketches:

- `src/basis_core/evaluation/operation_aware/engine.py` —
  `OperationAwareEvaluationEngine`. Stateless (no constructor arguments, no
  instance attributes). One public method:

  ```text
  evaluate(
      *,
      request: OperationAwareDecisionRequest,
      bundle: PolicyBundle,
      trace_id: str,
  ) -> EvaluationTrace
  ```

  `trace_id` is caller-supplied; the engine never generates one. It catches
  exactly one exception type, `SemanticPolicyValidationError` (from
  `policy.operation_aware.validation.validate_policy_bundle`), and maps it
  to a failed `EvaluationTrace` with
  `failure_reason=POLICY_VALIDATION_FAILURE`. It adds no
  `except Exception` clause anywhere — any other exception (a defect in its
  own wiring, or an unexpected failure inside a sibling module) propagates
  uncaught, by design (see the module's own "Unexpected-exception handling"
  docstring section): converting arbitrary exceptions into a governed
  failure category is explicitly left to "the future enforcement boundary,"
  not this pure orchestration engine.

- `src/basis_core/evaluation/operation_aware/response_assembly.py` — two
  pure functions:

  ```text
  assemble_operation_aware_decision_response(
      *,
      trace: EvaluationTrace,
      embed_evaluation_trace: bool,
  ) -> OperationAwareDecisionResponse

  assemble_audit_evidence(
      *,
      request: OperationAwareDecisionRequest,
      trace: EvaluationTrace,
      evidence_id: str,
      recorded_at: datetime,
  ) -> AuditEvidence
  ```

  Both treat `trace` as the single authoritative source of every final
  evaluation fact. `assemble_audit_evidence` additionally checks
  `request.request_id == trace.request_id` and
  `request.correlation_id == trace.correlation_id` and raises
  `EvaluationArtifactIdentityMismatchError` (a `ValueError` subclass) if
  either disagrees. `evidence_id` and `recorded_at` are caller-supplied;
  neither function calls a clock, generates an identifier, or uses
  randomness. Neither function invokes `OperationAwareEvaluationEngine` or
  any policy-owned operation.

- `src/basis_core/evaluation/operation_aware/trace_assembly.py` —
  `assemble_rule_evidence()` / `assemble_evaluation_trace()`, the pure
  rule-evidence/trace composition functions the engine calls internally.
  Not called directly by the future enforcement point; reached only through
  `OperationAwareEvaluationEngine.evaluate()`.

- `src/basis_core/decisions/operation_aware.py` —
  `OperationAwareDecisionRequest` (required `request_id`: no default
  factory, unlike v0.1's `DecisionRequest`; the producer, i.e.
  `basis-gateway`, must always supply it), `OperationAwareFailureReason`
  (closed six-value vocabulary: `INVALID_REQUEST`,
  `UNSUPPORTED_SCHEMA_VERSION`, `INVALID_POLICY_BUNDLE`,
  `POLICY_VALIDATION_FAILURE`, `CONDITION_EVALUATION_ERROR`,
  `INTERNAL_EVALUATION_ERROR`), `OperationAwareEvaluationStatus`
  (`COMPLETED` / `FAILED`), `OperationAwareDecisionOutcome` (`ALLOW` /
  `DENY` / `NOT_APPLICABLE`).

- `src/basis_core/audit/operation_aware/audit_evidence.py` —
  `AuditEvidence`. No `write`/`save`/`persist` method; no writer protocol;
  explicitly not persisted by `basis-core` (module docstring, "No
  persistence"). `evidence_id`, `recorded_at`, and every identifier field
  are caller-supplied with no default factory and no clock access.

- `src/basis_core/audit/operation_aware/evaluation_trace.py` —
  `EvaluationTrace`, `EvaluationStatus`, `TraceOutcome`,
  `TraceBundleApplicability`, `TraceFailureReason` (a six-value vocabulary
  local to `audit/`, value/member-parity-tested against
  `OperationAwareFailureReason` rather than importing it, since
  `evaluation_trace.py` predates the now-documented, still-unexercised
  `audit → decisions` permission — see that module's own "Vocabulary
  ownership" note).

None of these modules are re-exported from any package `__init__.py` today.
None of them constructs `OperationAwareEnforcementPoint`,
`OperationAwareEnforcementResult`, or `EnforcementDisposition` — those
symbols do not exist anywhere in the current tree
(`git grep` confirms zero matches). This ADR's job is to fix their shape
before PR 34 writes them.

### Architectural authority consulted

- `basis-architecture/docs/kernel-boundary-rules.md` — the
  `domain → {decisions, policy, audit} → evaluation → enforcement` (plus
  `adapters`) layer graph; `evaluation` may import `domain`, `decisions`,
  `policy`, `audit` and must not import `adapters`/`enforcement`;
  `enforcement` is the top layer and may import everything beneath it;
  nothing outside the application/runtime layer may import
  `basis_core.enforcement`.
- `basis-architecture/docs/architecture/operation-aware-evaluation-orchestration.md`
  (ADR-0006 in `basis-architecture`, a distinct document from this
  repository-local ADR-0006) — "The evaluation layer is not enforcement —
  it does not decide whether a decision is applied ... those remain owned
  by `enforcement` and `basis-gateway`." `enforcement` "invokes
  `evaluation`'s deterministic result; it does not redefine what that
  result means."
- `basis-architecture/docs/architecture/operation-aware-trace-audit-evidence.md`
  — "Trace explains evaluation. Audit records evidence. Gateway enforcement
  records what happened at runtime." §9 enumerates what only the gateway
  knows (enforcement outcome, which route was called, gateway correlation
  ID, gateway policy-loader state) and states plainly: "basis-core decides.
  basis-gateway enforces and records enforcement facts."
- `basis-architecture/docs/architecture/operation-aware-evaluation-semantics.md`
  §14 ("Safe Error Handling") — the six representative evaluation-failure
  categories (matching `OperationAwareFailureReason` exactly), and: "A
  kernel that cannot produce a valid decision must not default to `ALLOW`
  ... and it must not disguise an evaluation failure as a `DENY` or
  `NOT_APPLICABLE` decision." §15 restates boundary ownership: `basis-core`
  evaluates policy only; `basis-gateway` enforces decisions and handles
  runtime failure behavior.

These distinctions are adopted here unmodified:

```text
policy        owns executable authorization semantics
evaluation    orchestrates those semantics and assembles kernel artifacts
enforcement   converts the authoritative kernel result into a fail-closed
              caller-facing disposition
basis-gateway performs actual runtime/API enforcement and records
              gateway-only enforcement facts
```

---

## Decision

### 1. Additive coexistence

`OperationAwareEnforcementPoint` is a new class, a sibling of the existing
`EnforcementPoint`, added at `src/basis_core/enforcement/operation_aware.py`
(PR 34). It will not:

- modify `basis_core.enforcement.enforcement.EnforcementPoint`;
- overload `EnforcementPoint.evaluate()`'s signature or behavior;
- branch on request type inside v0.1 `evaluate()`;
- subclass `EnforcementPoint` merely to share implementation;
- change `EnforcementPoint.__init__`'s parameters
  (`engine`, `audit_writer`, `policy_version`);
- change v0.1 response, trace, audit, or failure semantics documented
  above;
- remove, rename, or reinterpret any symbol currently exported from
  `basis_core.enforcement`.

The two evaluation families differ in every dimension that would make
sharing an implementation force one class to understand two unrelated
systems:

- **Request contracts** — `DecisionRequest | dict[str, object]` (v0.1,
  dict accepted and validated inline) vs. a required, already-typed
  `OperationAwareDecisionRequest` (Decision 3 below — no dict form).
- **Engines** — `PolicyEngine`, a stateful-by-construction list of
  `PolicyRule` objects evaluated imperatively, vs.
  `OperationAwareEvaluationEngine`, a stateless orchestrator over a data
  model (`PolicyBundle`).
- **Response contracts** — `DecisionResponse` (four-value `FailureReason`,
  enforcement-boundary-scoped) vs. `OperationAwareDecisionResponse`
  (six-value `OperationAwareFailureReason`, evaluator-scoped, with a
  required-nullable `outcome`/`failure_reason` invariant `DecisionResponse`
  does not have).
- **Trace contracts** — `DecisionTrace`/`RuleEvaluation` (v0.1, assembled
  inline inside `_write_audit`) vs. `EvaluationTrace`/`TraceRuleEvidence`
  (assembled upstream, before enforcement ever sees them).
- **Audit artifacts** — a single `AuditEvent`, written synchronously via
  `AuditWriter.write()` inside `EnforcementPoint`, vs. a produced-but-never-
  written `AuditEvidence` (Decision 11 below) — structurally distinct
  families that do not share a base type, a writer protocol, or a schema
  version.
- **Failure vocabularies** — `FailureReason`
  (`MALFORMED_REQUEST`/`POLICY_ERROR`/`AUDIT_ERROR`/`INTERNAL_ERROR`, an
  enforcement-boundary concept) vs. `OperationAwareFailureReason`
  (`invalid_request`/`unsupported_schema_version`/`invalid_policy_bundle`/
  `policy_validation_failure`/`condition_evaluation_error`/
  `internal_evaluation_error`, an evaluator-result concept) — two
  independently versioned vocabularies that happen to share a field name,
  per `docs/implementation/basis-core-v0.2-operation-aware-plan.md` §2.2.
- **Constructor-time dependencies** — `PolicyEngine` + `AuditWriter` +
  optional `policy_version: str | None` (v0.1) vs.
  `OperationAwareEvaluationEngine` + `PolicyBundle` (Decision 2 below) — no
  `AuditWriter` at all, because the operation-aware point never writes
  audit (Decision 11).

Compatibility takes precedence over superficial reuse: a single class
accepting both request families would need runtime type dispatch inside a
method whose v0.1 contract (`docs/extension-contracts.md`, "EnforcementPoint
orchestration expectations") guarantees one simple, stable failure/audit
shape — exactly the kind of behavioral-breakage risk
`docs/breaking-change-discipline.md` flags under "Changing the signature of
a public function or method in an incompatible way."

### 2. Configuration model

`OperationAwareEnforcementPoint` is configured with:

```text
OperationAwareEvaluationEngine
PolicyBundle
```

It owns orchestration of those two configured dependencies. It does not
load policy from files, environment variables, databases, HTTP services, or
remote policy systems — policy loading and runtime lifecycle belong outside
`basis-core` (`basis-gateway`, or another runtime boundary). This mirrors
`EnforcementPoint`'s own existing constructor discipline (a pre-configured
`PolicyEngine`, never a policy *source*). The exact Python constructor
signature (parameter names, whether `PolicyBundle` is required at
construction vs. supplied per-call, keyword-only conventions) is a PR 34
implementation detail; only the two required dependencies and their
ownership are fixed here. Unlike v0.1 `EnforcementPoint`, no `AuditWriter`
is configured (Decision 11) and no `policy_version` string is configured —
`OperationAwareDecisionResponse.bundle_id`/`bundle_version` already carry
that provenance, sourced from the bundle itself via
`OperationAwareEvaluationEngine`/`assemble_operation_aware_decision_response`,
not from a constructor argument.

### 3. Accepted evaluation input

The initial v0.2 operation-aware enforcement surface accepts a typed
`OperationAwareDecisionRequest` only. It does not promise raw HTTP, JSON,
YAML, or arbitrary `dict`/mapping input — no `OperationAwareDecisionRequest
| dict[str, object]` union, unlike v0.1 `EnforcementPoint.evaluate()`.
Wire-format parsing and transport validation belong to `basis-gateway` or
another caller. Reasons typed input is preferable for this initial surface:

- **Request identity is available.** `OperationAwareDecisionRequest`
  requires `request_id` with no default factory (Decision 4) — a caller
  handing the enforcement point a raw mapping that fails to parse would
  force the enforcement point to invent a request identity for a request it
  never fully understood, exactly the situation v0.1's dict-validation-
  failure path already has to work around with a synthesized
  `str(raw.get("request_id") or uuid.uuid4())` (a UUID generation this ADR
  explicitly forbids for the operation-aware surface — Decision 4).
- **Contracts are already validated.** `OperationAwareDecisionRequest`'s
  own construction-time Pydantic validation (`decisions/operation_aware.py`)
  already enforces field presence, type, and pattern/enum shape before the
  enforcement point ever sees it — Stage 1/2 of the Section 7 pipeline in
  the v0.2 roadmap plan are satisfied by construction, not re-implemented
  here.
- **Transport behavior stays outside the kernel**, consistent with
  `docs/kernel-constitution.md` Invariant 2 ("The kernel evaluates; it does
  not transport"), applied identically to both enforcement points.
- **The enforcement point does not need to invent a request ID for
  malformed wire input** — see the first bullet. Accepting raw input would
  reintroduce exactly the synthesized-identity special case this ADR
  removes by requiring a typed request.
- **The kernel remains deterministic and transport-agnostic** — accepting
  and rejecting raw mappings is itself a (small) transport-adjacent
  responsibility; keeping it entirely outside `basis-core` matches
  `operation-aware-evaluation-semantics.md` §15's restated boundary
  ("`basis-core` evaluates policy only").

Any future raw-mapping convenience API is out of scope for PR 34 and would
require separate review.

### 4. Caller-supplied deterministic facts

The caller supplies every fact that would otherwise require a clock or
randomness:

- `trace_id` — passed to `OperationAwareEvaluationEngine.evaluate(trace_id=...)`
  today; `OperationAwareEnforcementPoint` accepts it from its own caller and
  forwards it unchanged. Confirmed by the engine's current signature and its
  own docstring ("`trace_id` is supplied by the caller; the engine never
  generates one").
- `evidence_id` and `recorded_at` — passed to
  `assemble_audit_evidence(evidence_id=..., recorded_at=...)` today, both
  with no default factory and no clock access, confirmed directly in
  `audit_evidence.py`'s and `response_assembly.py`'s docstrings and
  implementations.

`basis-core` — including the future `OperationAwareEnforcementPoint` — must
not generate UUIDs, timestamps, random identifiers, or any other
environment-dependent value for any of these three facts. This is a
continuation of behavior already true of every function
`OperationAwareEnforcementPoint` will compose (`OperationAwareEvaluationEngine.evaluate()`,
`assemble_operation_aware_decision_response()`, `assemble_audit_evidence()`
— none of the three calls a clock, a UUID generator, or a random-value
source today), not a new constraint invented by this ADR. The enforcement
point validates and preserves these caller-supplied facts; it does not
derive them from wall-clock time or randomness. This is a deliberate
divergence from v0.1 `EnforcementPoint`, whose `DecisionRequest.request_id`
*does* default-factory a UUID and whose `AuditEvent.timestamp` is
system-clock-defaulted — the operation-aware surface is stricter here by
design, matching `OperationAwareDecisionRequest.request_id`'s own already-
established no-default-factory precedent (Decision 3).

### 5. Evaluation and assembly flow

```text
typed OperationAwareDecisionRequest
    +
configured PolicyBundle
    +
caller-supplied artifact facts (trace_id, evidence_id, recorded_at)
        ↓
OperationAwareEvaluationEngine.evaluate(request=..., bundle=..., trace_id=...)
        ↓
EvaluationTrace
        ↓
assemble_operation_aware_decision_response(trace=..., embed_evaluation_trace=...)
        → OperationAwareDecisionResponse
assemble_audit_evidence(request=..., trace=..., evidence_id=..., recorded_at=...)
        → AuditEvidence
        ↓
OperationAwareEnforcementResult (Decision 6)
```

`OperationAwareEnforcementPoint.evaluate()` must not: re-evaluate
selectors, re-evaluate conditions, recompute aggregation, reinterpret trace
facts, recreate response/trace agreement logic, or duplicate any
response-assembly mapping. Every one of those operations is already
implemented and already merged in `policy/operation_aware/`,
`evaluation/operation_aware/engine.py`, and
`evaluation/operation_aware/response_assembly.py`. The enforcement point's
job is composition and fail-closed containment (Decisions 8–9) — invoking
already-authoritative functions in the order above, in one place, and
translating their result into a disposition. The merged evaluation and
assembly components remain the authoritative source of every evaluation
fact; nothing in `enforcement/` is permitted to disagree with them.

### 6. Enforcement result carrier

PR 34 introduces an enforcement-owned result carrier, provisionally named
`OperationAwareEnforcementResult`, under `basis_core.enforcement`
(`src/basis_core/enforcement/operation_aware.py`, alongside
`OperationAwareEnforcementPoint` itself). Its conceptual fields:

```text
response:       OperationAwareDecisionResponse
audit_evidence: AuditEvidence | None
disposition:    EnforcementDisposition   (Decision 7)
```

Whether it is implemented as a frozen dataclass or a frozen Pydantic model
is a PR 34 implementation detail; either satisfies this decision provided
it is immutable and rejects undeclared fields (see the PR 34 test matrix,
item 20). It is not a new `basis-schemas` contract — `basis-schemas`
publishes shared, cross-repository contracts; this carrier exists only to
hand a caller three already-fully-specified artifacts together, and has no
independent wire format of its own to publish. It is not added to any
package's public exports in PR 33 or PR 34; public export is Milestone 11,
PR 35's decision, per the accepted roadmap.

A carrier is necessary because:

- **Callers need both response and evidence.** A caller (`basis-gateway`)
  that enforces a decision needs `OperationAwareDecisionResponse` to know
  the authorization outcome and needs `AuditEvidence` to assemble its own
  `GatewayAuditEvent` (Decision 12) — both artifacts from one evaluation,
  not two separately-timed calls that risk observing different evaluation
  runs.
- **Enforcement disposition must remain separate from kernel outcome.**
  `disposition` is an enforcement-only concept (Decision 7); conflating it
  with `response.outcome` would erase the distinction between "the
  evaluator says X" and "the enforcement boundary's own allow/deny
  conclusion is Y" — a distinction Decision 7's `NOT_APPLICABLE`/`failed`
  examples depend on.
- **Adding `AuditEvidence` or a disposition field to
  `OperationAwareDecisionResponse` would be an unauthorized contract
  change.** `OperationAwareDecisionResponse` is a published, shared
  `basis-schemas` contract shape (`operation-aware-decision-response`);
  extending it for local `basis-core` enforcement convenience is exactly
  the kind of change `docs/breaking-change-discipline.md` requires
  cross-repository review for, and this ADR does not perform that review.
- **A bare tuple would obscure meaning and future compatibility
  expectations.** An unnamed `(response, evidence, disposition)` tuple
  gives a caller no field names to pattern-match on, no way to add a fourth
  field later without breaking positional unpacking, and no docstring
  anchor — the same reasoning that led every other operation-aware model in
  this codebase (`EvaluationTrace`, `AuditEvidence`,
  `OperationAwareDecisionResponse`) to be a named, validated type rather
  than a dict or tuple.

### 7. Enforcement disposition

A two-value `EnforcementDisposition`: `allow` / `deny`. This is not the
kernel authorization outcome (`OperationAwareDecisionOutcome`, three
values: `allow`/`deny`/`not_applicable`).

`disposition = allow` only when **all** of the following hold:

- evaluation completed successfully (no unexpected exception escaped any
  stage);
- the authoritative kernel outcome (`response.outcome`) is `allow`;
- response and evidence assembly both completed successfully;
- no unexpected internal exception occurred anywhere in the composed flow.

`disposition = deny` for every other case, including:

- authoritative kernel outcome `deny`;
- default deny (a `deny` outcome reached via no matched allow rule — this
  is already folded into `response.outcome = deny` by policy-owned
  aggregation; the enforcement point does not distinguish it further);
- authoritative kernel outcome `not_applicable`;
- `response.evaluation_status = failed` (for any of the six governed
  `OperationAwareFailureReason` categories);
- response or evidence assembly failure;
- unexpected internal failure (Decision 9).

The enforcement point never rewrites the response to match the disposition.
Two required examples, both already representable by the merged
`OperationAwareDecisionResponse`/`EvaluationTrace` invariants:

```text
response.outcome = not_applicable
disposition = deny
```

```text
response.evaluation_status = failed
response.outcome = null
disposition = deny
```

Failure remains distinct from denial in the authoritative kernel artifacts
— `response.outcome` is never coerced to `deny` merely because
`disposition` happens to be `deny` in both the `not_applicable` and
`failed` cases. This preserves exactly the distinction
`operation-aware-evaluation-semantics.md` §14 requires ("it must not
disguise an evaluation failure as a `DENY` or `NOT_APPLICABLE` decision"):
the kernel-facing artifacts stay honest; only the enforcement-local,
non-published `disposition` field collapses the three non-allow states
into one caller-facing "do not proceed" signal, mirroring the same
collapse v0.1 `EnforcementPoint` already performs at its own
`AuditOutcome` boundary (`NOT_APPLICABLE → AuditOutcome.DENIED`) without
ever touching `DecisionResponse.outcome` itself.

### 8. Expected evaluator failure

When `OperationAwareEvaluationEngine.evaluate()` returns a valid failed
`EvaluationTrace` (today, reachable via `SemanticPolicyValidationError` →
`POLICY_VALIDATION_FAILURE`, or via a rule condition error →
`CONDITION_EVALUATION_ERROR` through policy-owned aggregation — see the
engine's own docstring, "Condition-evaluation-error propagation"), the
enforcement point must not treat that as an escaped Python exception. It
must:

- assemble the corresponding failed `OperationAwareDecisionResponse`
  (`assemble_operation_aware_decision_response`, unchanged, called
  normally);
- assemble `AuditEvidence` (`assemble_audit_evidence`, unchanged, called
  normally — a failed trace is still a valid, fully-specified trace with a
  `request_id`/`correlation_id` the identity-agreement check can verify);
- preserve the governed failure reason (`response.failure_reason`, mapped
  from `trace.failure_reason` exactly as `response_assembly.py` already
  does — no reinterpretation);
- preserve `outcome = null` (already guaranteed by
  `OperationAwareDecisionResponse`'s own construction-time invariant);
- return `disposition = deny` (Decision 7).

A failed evaluation is a valid, explainable kernel result, not an
enforcement-point error path. `AuditEvidence` is present and trustworthy in
this case — this is the case Decision 6's "callers need both response and
evidence" reasoning depends on: a caller diagnosing why an evaluation
failed needs both artifacts together.

### 9. Unexpected exceptions

`OperationAwareEnforcementPoint.evaluate()` must never allow an exception
to reach its caller. It must contain unexpected exceptions arising from:

- evaluation orchestration (any exception from
  `OperationAwareEvaluationEngine.evaluate()` other than the
  `SemanticPolicyValidationError` the engine already converts internally —
  the engine's own docstring is explicit that everything else "propagates
  uncaught" and that converting it is "the future enforcement boundary's
  responsibility");
- trace handling;
- response assembly (`assemble_operation_aware_decision_response`);
- `AuditEvidence` assembly (`assemble_audit_evidence`, including a raised
  `EvaluationArtifactIdentityMismatchError` — a caller-input-consistency
  bug, not an authorization outcome, but still an exception this method
  must not leak);
- result-carrier construction;
- internal mapping or validation code inside the enforcement point itself.

The only existing governed internal-error failure reason for this purpose
is `OperationAwareFailureReason.INTERNAL_EVALUATION_ERROR` (confirmed
present in `decisions/operation_aware.py`'s six-value closed vocabulary,
and named explicitly in `operation-aware-evaluation-semantics.md` §14 as
"an unexpected failure within the evaluation process itself, not
attributable to the request or policy bundle"). No suitable existing value
is missing; no new failure vocabulary is invented by this ADR or by PR 34.

For an unexpected failure:

```text
response:
    evaluation_status = failed
    outcome = null
    failure_reason = OperationAwareFailureReason.INTERNAL_EVALUATION_ERROR

disposition:
    deny
```

`audit_evidence` may be absent (`None`) only when trustworthy evidence
cannot be assembled without reusing the failing path or fabricating
contradictory facts — for example, if the exception occurred before a
valid `EvaluationTrace` existed at all, there is no honest `trace_id` to
attach evidence to, and `assemble_audit_evidence` itself cannot run without
one. The enforcement point must not fabricate a successful-looking or
partially contradictory `AuditEvidence` merely to make the field non-null.

This ADR distinguishes the two failure classes explicitly:

```text
expected evaluator failure (Decision 8)
    → failed response + valid AuditEvidence + deny disposition

unexpected catastrophic assembly/internal failure (Decision 9)
    → failed response + no untrustworthy fabricated evidence + deny disposition
```

Both classes share the same `response.outcome = null` and
`disposition = deny` shape; they differ only in whether `audit_evidence` is
reliably constructible and, when it is, in `failure_reason`
(`INTERNAL_EVALUATION_ERROR` for the unexpected case; the six governed
categories, as appropriate, for the expected case).

### 10. Trace presentation

The operation-aware response contract already supports both approved trace
forms: embedded (`response.evaluation_trace` set) and reference-only
(`response.trace_id` set, `response.evaluation_trace = None`), controlled
today by `assemble_operation_aware_decision_response`'s required
`embed_evaluation_trace: bool` keyword argument. `OperationAwareEnforcementPoint`
preserves this existing response-assembly behavior unchanged for both
forms — it does not alter, wrap, or reinterpret
`assemble_operation_aware_decision_response`'s output. The exact caller
option or argument name `OperationAwareEnforcementPoint.evaluate()` itself
exposes to control trace embedding (a boolean parameter, a per-call
override, a construction-time default, or some combination) is finalized
in PR 34 after inspecting the merged assembly API directly at
implementation time; this ADR fixes only that the choice must be surfaced
to the caller in some form and must not be hardcoded to always-embed or
always-reference-only without a caller-visible override, matching
`response_assembly.py`'s own "explicit caller choice, never inferred"
design.

### 11. Audit boundary

`basis-core` — including `OperationAwareEnforcementPoint` — produces
`AuditEvidence`. It does not:

- persist it;
- send it over a network;
- write it through `AuditWriter` (the v0.1 protocol is shaped for
  `AuditEvent`, a structurally distinct type; it is never adapted or
  reused for `AuditEvidence`);
- create a new `AuditEvidence`-writer-shaped protocol of any kind;
- create logs or metrics as a substitute for persistence;
- construct `GatewayAuditEvent`.

`GatewayAuditEvent` requires runtime facts the kernel structurally does not
possess — which route was called, what was returned to the caller, whether
enforcement succeeded, gateway-instance identity, gateway correlation ID,
gateway policy-loader state
(`operation-aware-trace-audit-evidence.md` §9). None of that exists inside
`OperationAwareEnforcementPoint.evaluate()`, exactly as none of it exists
inside v0.1 `EnforcementPoint.evaluate()` today. That artifact remains a
`basis-gateway` responsibility. The existing v0.1 `AuditEvent` and
`AuditWriter` (and `NullAuditWriter`/`LogAuditWriter`) are unchanged by
this ADR and by PR 34 — `OperationAwareEnforcementPoint` does not accept an
`AuditWriter` at construction (Decision 2) and has no code path that could
invoke one.

### 12. Gateway boundary

Explicitly deferred to `basis-gateway` or another runtime boundary,
unchanged by this ADR: authentication; JWT/OIDC processing;
identity-provider interaction; raw transport parsing; HTTP status codes;
policy loading and reload; policy distribution; network command execution;
protocol command suppression or delivery; retries; persistence; audit
delivery; `GatewayAuditEvent`; readiness; telemetry; runtime logging and
metrics; degraded-site operating modes.

`OperationAwareEnforcementPoint.evaluate()` returns a disposition. It does
not perform physical or network enforcement of any kind — the same
boundary v0.1 `EnforcementPoint` already respects (it returns a
`DecisionResponse`; it does not, for example, close a relay or reject an
HTTP request itself).

### 13. Purity and execution model

The operation-aware enforcement path remains synchronous, deterministic
for equivalent inputs, side-effect free, offline, free of network access,
free of filesystem access, free of database access, free of clocks, free
of randomness, free of persistence, and free of protocol-specific
behavior — inheriting this from every function it composes
(`OperationAwareEvaluationEngine.evaluate()`,
`assemble_operation_aware_decision_response()`,
`assemble_audit_evidence()`, none of which perform I/O today) and adding no
new source of nondeterminism itself. It must not mutate: the request; the
policy bundle; the evaluation trace; the response; the `AuditEvidence`. All
four already-merged types it handles are frozen/immutable Pydantic models
(`ConfigDict(frozen=True, extra="forbid")` on `OperationAwareDecisionRequest`,
`OperationAwareDecisionResponse`, `AuditEvidence`, `EvaluationTrace`), so
in-place mutation is already structurally prevented by the types
themselves; this decision states the enforcement point must not attempt to
work around that (e.g., no `model_copy(update=...)` used to produce a
"corrected" response that disagrees with the trace).

### 14. Public API coexistence

Intended future imports, conceptually:

```text
from basis_core.enforcement import EnforcementPoint
from basis_core.enforcement import OperationAwareEnforcementPoint  # future
```

Both coexist; neither replaces the other. This ADR (PR 33) does not change
`__all__`, `docs/public-api.md`, or any package's exports. Neither will
PR 34 — `OperationAwareEnforcementPoint`,
`OperationAwareEnforcementResult`, and `EnforcementDisposition` are
implemented in PR 34 as internal-to-the-package symbols, following the
same "not yet re-exported" pattern every other operation-aware module in
this roadmap has followed since PR 5. Public export path, naming in
`docs/public-api.md`, and `__all__` placement are PR 35's decision, made
after PR 34's implemented surface has stabilized and can be reviewed as a
whole — matching the roadmap's own stated Milestone 11 sequencing (PR 33 →
PR 34 → PR 35).

---

## Rejected Alternatives

**Modify v0.1 `EnforcementPoint`.** Rejected: risks behavioral and
constructor compatibility for every existing consumer, and forces one class
to understand two unrelated request/evaluation/audit families at once (see
Decision 1's per-dimension comparison).

**Branch inside v0.1 `evaluate()` based on request type.** Rejected:
behavior would depend on runtime input type, silently expanding a
stabilized public method's contract
(`docs/extension-contracts.md`'s "EnforcementPoint orchestration
expectations" already documents a single, simple failure/audit shape for
this method) in a way `docs/breaking-change-discipline.md` treats as
incompatible.

**Subclass v0.1 `EnforcementPoint`.** Rejected: creates an implicit
compatibility relationship between two independently governed surfaces —
a future change to `EnforcementPoint`'s internals (even one that stays
within its own stable contract) could silently break the subclass — and
encourages reuse of `EnforcementPoint`'s own `AuditEvent`/`FailureReason`
behavior, which is structurally incompatible with `AuditEvidence`/
`OperationAwareFailureReason` (Decision 1).

**Return only `OperationAwareDecisionResponse`.** Rejected: callers also
require bounded `AuditEvidence` (Decision 6) and an enforcement-only
disposition (Decision 7) that must not be folded into the published
response contract (see the next rejected alternative).

**Add `AuditEvidence` or `disposition` fields to
`OperationAwareDecisionResponse`.** Rejected: the response is a published,
shared `basis-schemas` contract; changing it merely for local `basis-core`
enforcement convenience is an unauthorized, unreviewed contract change
(Decision 6).

**Convert failed evaluation or `NOT_APPLICABLE` into response `DENY`.**
Rejected: destroys the governed distinction between evaluator failure,
non-applicability, and denial that
`operation-aware-evaluation-semantics.md` §14 and every already-merged
model's `outcome`-null-iff-`failed` invariant establish (Decision 7,
Decision 8).

**Generate IDs or timestamps inside `basis-core`.** Rejected: clocks and
randomness violate the determinism `docs/kernel-constitution.md` Invariant
5 already requires of the v0.1 kernel and that every merged operation-aware
function already honors (Decision 4).

**Persist `AuditEvidence` in `basis-core`.** Rejected: persistence and
delivery belong to runtime components (`basis-gateway`), per
`operation-aware-trace-audit-evidence.md`'s explicit "basis-core does not
persist audit" position (Decision 11).

**Construct `GatewayAuditEvent` in `basis-core`.** Rejected: the kernel
structurally does not know whether, or how, enforcement actually occurred
(Decision 11, Decision 12).

**Add asynchronous or I/O-bearing enforcement.** Rejected: the kernel
remains synchronous, embeddable, and offline, per
`docs/kernel-constitution.md` Invariant 1, extended unchanged to
`evaluation/` and now to the operation-aware enforcement surface
(Decision 13).

---

## PR 34 Required Test Contract

PR 34 (`OperationAwareEnforcementPoint` implementation) must include tests
proving:

1. Existing v0.1 `EnforcementPoint` behavior and public import paths are
   unchanged (`tests/test_enforcement_point.py` passes unmodified).
2. A completed allow evaluation returns: authoritative
   `response.outcome = allow`; valid `AuditEvidence`; `disposition = allow`.
3. An explicit deny evaluation returns: authoritative
   `response.outcome = deny`; valid `AuditEvidence`; `disposition = deny`.
4. Default deny (no matched allow rule, applicable bundle) remains
   `response.outcome = deny` and `disposition = deny`.
5. `NOT_APPLICABLE` remains `response.outcome = not_applicable` while
   `disposition = deny`.
6. Every governed evaluator failure (reachable
   `OperationAwareFailureReason` category) returns:
   `evaluation_status = failed`; `outcome = null`; the original governed
   `failure_reason`; valid `AuditEvidence`; `disposition = deny`.
7. An unexpected engine exception does not escape `evaluate()` and returns
   a failed `internal_evaluation_error` response plus `disposition = deny`.
8. An unexpected response-assembly exception does not escape.
9. An unexpected `AuditEvidence`-assembly exception (including a raised
   `EvaluationArtifactIdentityMismatchError`) does not escape.
10. Catastrophic assembly failure does not fabricate contradictory
    `AuditEvidence` (either `audit_evidence` is a trustworthy record or it
    is `None` — never a record whose facts disagree with `response`).
11. Caller-supplied `trace_id` is preserved verbatim in the response/trace.
12. Caller-supplied `evidence_id` is preserved verbatim in `AuditEvidence`.
13. Caller-supplied `recorded_at` is preserved verbatim in `AuditEvidence`.
14. Embedded-trace and reference-only response forms are both reachable
    and preserved, per the merged `assemble_operation_aware_decision_response`
    `embed_evaluation_trace` behavior (Decision 10).
15. Equal inputs (request, bundle, `trace_id`, `evidence_id`,
    `recorded_at`) and caller facts produce equal outputs (determinism).
16. Inputs (request, bundle) are not mutated by `evaluate()`.
17. No clock, UUID, randomness, network, filesystem, database, environment,
    subprocess, or persistence dependency is introduced anywhere in the new
    module.
18. No `AuditWriter`-equivalent protocol is introduced for `AuditEvidence`.
19. No `GatewayAuditEvent` is imported or constructed anywhere in the new
    module.
20. The new result carrier (`OperationAwareEnforcementResult`) is immutable
    and rejects undeclared fields (if implemented as a Pydantic model,
    `frozen=True, extra="forbid"`; if a dataclass, `frozen=True` plus a
    construction-time or type-level rejection of unexpected keys).
21. No public export is added — `OperationAwareEnforcementPoint`,
    `OperationAwareEnforcementResult`, and `EnforcementDisposition` are not
    present in any `__all__`, any package `__init__.py`, or
    `docs/public-api.md` after PR 34 (public export remains PR 35).
22. Existing import-boundary tests remain green, and (if the roadmap's
    existing recursive `tests/test_import_boundaries.py` guard does not
    already cover `enforcement/operation_aware.py` by directory-recursive
    scanning) a boundary test confirms
    `src/basis_core/enforcement/operation_aware.py` imports only from
    `evaluation/`, `decisions/`, `audit/`, `domain/`, and `policy/` (all
    legal for `enforcement/` per `docs/import-boundaries.md`), and does not
    import `adapters/` unless a future PR establishes a reason to.

---

## Consequences

**For `basis-core`:** PR 34 has a settled target — one new file
(`src/basis_core/enforcement/operation_aware.py`), one new class plus one
new result-carrier type plus one new two-value enum, composing three
already-implemented, already-tested functions
(`OperationAwareEvaluationEngine.evaluate`,
`assemble_operation_aware_decision_response`, `assemble_audit_evidence`)
behind a fail-closed `evaluate()` that never raises. No existing file
changes. No new runtime dependency. No public API change.

**For `basis-gateway`:** once PR 34 lands, `basis-gateway` has a concrete,
typed contract (`OperationAwareEnforcementResult`) to build its own
`GatewayAuditEvent` and enforcement decision from, without needing to
reconstruct evaluation facts itself or guess at a disposition mapping.

**For future work:** PR 35 (public API surface update) inherits a fully
implemented, fully tested surface to decide the export path for, rather
than having to make packaging decisions concurrently with behavioral ones.

## Related Documents

- `docs/implementation/basis-core-v0.2-operation-aware-plan.md` — Section
  5 ("Compatibility strategy," the original "new class, not a modified
  `evaluate()` signature" recommendation this ADR formalizes), Section 7
  (the sixteen-stage deterministic evaluation pipeline this ADR's Decision
  5 flow summarizes), Milestone 11 (PR 33/34/35 sequencing).
- `docs/extension-contracts.md` — "EnforcementPoint orchestration
  expectations," unchanged, and the model this ADR's Decision 1 compares
  the operation-aware surface against.
- `docs/kernel-constitution.md` — Invariant 1 (isolation, extended to
  `evaluation/`), Invariant 5 (determinism), Invariant 6 (fail-closed
  enforcement) — all inherited unchanged by the operation-aware
  enforcement surface.
- `docs/import-boundaries.md` — the `enforcement/` permission row
  (`may import from: policy/, audit/, evaluation/, decisions/, adapters/,
  domain/`) this ADR's Decision 5/PR 34 test-matrix item 22 depend on.
- `docs/breaking-change-discipline.md` — the "Changing the signature of a
  public function or method in an incompatible way" and contract-change
  review process this ADR's Decision 1 and rejected-alternatives section
  invoke.
- `basis-architecture/docs/kernel-boundary-rules.md` — the layer graph and
  `enforcement`/`evaluation` ownership split this ADR adopts unmodified.
- `basis-architecture/docs/architecture/operation-aware-evaluation-orchestration.md`
  — "the evaluation layer is not enforcement," the boundary this ADR's
  Decision 1 and Decision 5 rest on.
- `basis-architecture/docs/architecture/operation-aware-trace-audit-evidence.md`
  — §9 ("Gateway Enforcement Evidence"), the basis for Decision 11 and
  Decision 12's audit/gateway boundary.
- `basis-architecture/docs/architecture/operation-aware-evaluation-semantics.md`
  — §14 ("Safe Error Handling"), the basis for Decision 7's disposition
  mapping and Decision 9's governed internal-error failure reason.
- ADR-0005 (`docs/adr/ADR-0005-move-jwt-normalization-outside-kernel.md`)
  — the most recent prior repository-local ADR; this document follows its
  structure and numbering convention.
