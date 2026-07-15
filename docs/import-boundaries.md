# Import Boundaries

This document defines the allowed dependency direction between `basis_core` subpackages and the constraints on what may enter the kernel at all. It is the implementation specification for the architectural requirements stated in `docs/kernel-boundary-rules.md` in basis-architecture, extended by `basis-architecture` ADR-0006 ("Introduce a Pure Evaluation Orchestration Layer"), which adds `evaluation/` as a first-class kernel package. That document is the architectural authority; this document is the implementation detail.

`basis_core` is not a simple linear chain of layers — it is a **directed acyclic import graph**. Several packages sit at the same depth and do not import each other (`policy/` and `audit/` are mutually isolated siblings; so are `policy/` and `evaluation/`'s policy-facing role versus `audit/`'s trace-facing role). The per-package permission matrix below is the authoritative statement of the graph; any diagram in this document or in `docs/implementation/basis-core-v0.2-operation-aware-plan.md` is a simplified illustration of that matrix, not a substitute for it.

Violations of these boundaries are bugs, not style issues. A module that imports from a layer above it introduces a circular dependency risk and erodes the testability of the lower layer. A module that imports a framework, database client, or protocol library violates the kernel isolation that makes basis-core embeddable, testable, and portable.

## Architecture ceilings and local restrictions

The permission matrix below states **maximum permitted dependencies** for each kernel package, per `basis-architecture`'s `docs/kernel-boundary-rules.md`. That matrix is a ceiling, not a mandate: a package is not required to use every import it is architecturally entitled to, and an implementation subtree within a package may impose a **stricter local rule** than its package's architecture ceiling, provided the local rule only narrows the ceiling and never permits an import the architecture matrix forbids outright.

`policy/` is the concrete case in this document: the architecture ceiling permits `policy/` to import `domain/` and `decisions/`. The operation-aware surface (`policy/operation_aware/`) already uses that full ceiling. The legacy v0.1 top-level modules (`policy/engine.py`, `policy/rules.py`) intentionally retain a stricter local rule — `domain/` only, no `decisions/` — enforced by `tests/test_models.py::test_policy_does_not_import_from_decisions`. Both are correct simultaneously: the stricter local rule narrows the architecture ceiling for that specific subtree; it does not contradict or expand it. This is not a general exception mechanism — a local rule may only remove permission the ceiling grants, never add an import the ceiling forbids (e.g., no local rule could ever permit `policy/` to import `audit/`, ceiling or no ceiling).

## Allowed dependencies

```
enforcement/
  ├── may import from: policy/, audit/, evaluation/, decisions/, adapters/, domain/
  └── must not be imported by: any other basis_core subpackage

evaluation/
  ├── may import from: domain/, decisions/, policy/, audit/
  └── must not import from: adapters/, enforcement/

adapters/
  ├── may import from: domain/, decisions/, policy/
  └── must not import from: audit/, evaluation/, enforcement/

audit/
  ├── may import from: domain/, decisions/
  └── must not import from: policy/, evaluation/, adapters/, enforcement/

policy/  (architecture ceiling — see "Architecture ceilings and local restrictions" above)
  ├── may import from: domain/, decisions/
  └── must not import from: audit/, evaluation/, adapters/, enforcement/

  policy/operation_aware/  (uses the full ceiling)
    ├── may import from: domain/, decisions/, policy/ siblings
    └── must not import from: audit/, evaluation/, adapters/, enforcement/

  policy/engine.py, policy/rules.py  (legacy v0.1 — stricter local rule)
    ├── may import from: domain/
    └── must not import from: decisions/, audit/, evaluation/, adapters/, enforcement/

decisions/
  ├── may import from: domain/
  └── must not import from: policy/, audit/, evaluation/, adapters/, enforcement/

domain/
  ├── may import from: (nothing in basis_core)
  └── must not import from: any other basis_core subpackage
```

**Note on `audit/` and `decisions/`:** `audit/` is documented as permitted to import `decisions/` because `basis-architecture`'s `docs/kernel-boundary-rules.md` states this as part of the architecture ceiling. No current `audit/` module (top-level or `audit/operation_aware/`) imports `decisions/` today — this is alignment with the architecture ceiling, not a new runtime dependency. Documenting the permission does not require introducing an import, and no code or test was added to exercise it.

**Note on `adapters/` and `policy/`:** `adapters/` is documented as permitted to import `policy/` because `basis-architecture`'s `docs/kernel-boundary-rules.md` states this as part of the architecture ceiling — adapters may read policy contracts to know what a valid decision request/policy shape looks like. This dependency is intentionally **one-way and asymmetric**: `adapters` may import `policy`, but `policy` must never import `adapters` (see the matrix above and `tests/test_import_boundaries.py::test_policy_does_not_import_from_adapters`). An asymmetric edge does not break the graph's acyclic property — it is simply not reversed. No current `basis_core.adapters` module imports `policy/` today; this permission, like `audit/`'s `decisions/` permission, is unexercised ceiling alignment, not a new dependency. This document governs the internal `basis_core.adapters` subpackage only. It makes no claim about the external `basis-adapters` repository's implementation responsibilities, which are a separate, differently-scoped component; nothing here modifies that repository's architecture documentation.

**Note on `policy/` and `decisions/`:** the architecture ceiling permits `policy/` to import `decisions/`, and `policy/operation_aware/` already uses that permission (`policy/operation_aware/{applicability,selector,operators,condition_eval}.py` all import `OperationAwareDecisionRequest` from `decisions/operation_aware.py`). The legacy v0.1 top-level modules — `policy/engine.py` and `policy/rules.py` — intentionally retain the stricter pre-operation-aware rule: `domain/` only, no `decisions/` import. This is enforced today by `tests/test_models.py::test_policy_does_not_import_from_decisions`, which scans only `policy/*.py` non-recursively (`pkg_dir.glob("*.py")`) and therefore does not — and was never intended to — reach `policy/operation_aware/*.py`. That test remains valid and is unchanged: it protects exactly the subtree it was written for, not the whole `policy/` package. The architecture ceiling and the legacy local rule are both true at once, at different scopes, not in contradiction: `policy/`'s ceiling is `domain/` + `decisions/`; `policy/engine.py`/`policy/rules.py`'s local rule narrows that ceiling to `domain/` only; `policy/operation_aware/`'s modules use the full ceiling.

As a directed acyclic graph, the permitted edges are:

```
                        domain/
                           ↑
                        decisions/
                        ↑        ↑
                    policy/    audit/
                    ↑      ↖   ↗   ↑
                    │    evaluation/
                    │        ↑
              adapters/      │
                    ↑        │
                    └── enforcement/
```

Read the arrows as "imports from." `policy/` and `audit/` are siblings that do not import each other. `evaluation/` imports both `policy/` and `audit/` legally — it is the one package permitted to sit above both — but neither `policy/` nor `audit/` may import `evaluation/` or each other. `adapters/` legally imports `policy/` (an edge not shown as a separate arrow above to keep the diagram readable — see the permission matrix, which is authoritative); this is not reversed anywhere, so the graph remains acyclic despite this edge not being symmetric with anything else in the diagram. This diagram is illustrative and intentionally does not encode the `policy/` architecture-ceiling-versus-legacy-local-rule distinction (see the matrix above and the "Architecture ceilings and local restrictions" section); the permission matrix is the authoritative statement of both the package-level ceiling and the subtree-level local rules.

## Rationale for each constraint

**`domain/` has no basis_core imports.** Domain types are the shared vocabulary of the entire library. If `domain/` imported from `policy/` or `decisions/`, those packages could not safely import from `domain/` without creating a cycle. The domain layer must remain a dependency sink.

**`policy/` architecture ceiling: `domain/` and `decisions/`; actual permission is subtree-dependent.** The policy engine reasons about subjects, resources, actions, and — for the operation-aware surface — the request envelope itself (`OperationAwareDecisionRequest`, to evaluate applicability, selectors, and conditions against it). It does not need to know about audit plumbing (`audit/`), evaluation orchestration (`evaluation/`), or enforcement orchestration (`enforcement/`). Keeping `policy/` isolated from `audit/` and `evaluation/` means it can be tested without either: construct a bundle/request, call the policy-owned evaluator, check the result. `policy/` owns executable authorization semantics — applicability, candidate selection, selector matching, condition evaluation, condition-result aggregation, rule-effect aggregation, deny precedence, allow determination, default deny, `NOT_APPLICABLE` determination, and final authorization-outcome semantics — and nothing above it may reimplement that logic. Within this ceiling, two subtrees exist: `policy/operation_aware/{applicability,selector,operators,condition_eval}.py` use the full ceiling (`domain/` + `decisions/`) today; the legacy v0.1 modules `policy/engine.py` and `policy/rules.py` retain a stricter local rule (`domain/` only), enforced by `tests/test_models.py::test_policy_does_not_import_from_decisions`. See "Architecture ceilings and local restrictions" above.

**`decisions/` imports only `domain/`.** `DecisionRequest` and `DecisionResponse` (and their operation-aware counterparts) are the data contracts at the enforcement boundary. They reference domain types (via field names and string identifiers) but do not import the policy engine, audit machinery, or evaluation orchestration. This keeps the contract types lightweight and independently usable.

**`audit/` imports `domain/` and `decisions/`.** `AuditEvent` (and the operation-aware `TraceRuleEvidence`/`EvaluationTrace` models) record the full context of a decision: subject fields (from `domain/`), action, resource, and outcome. The audit layer owns bounded trace and audit-evidence contracts. It does not import the policy engine, the evaluation orchestration layer, or the enforcement orchestration layer — and `policy/` does not import `audit/` either. The two are mutually isolated siblings; only `evaluation/` is permitted to sit above both. The `decisions/` permission is architecture-ceiling alignment, per `basis-architecture`'s `docs/kernel-boundary-rules.md`: no current `audit/` module (top-level or `audit/operation_aware/`) imports `decisions/`. Documenting the permission is not the same as introducing a dependency; no code or test was added to exercise it.

**`evaluation/` imports `domain/`, `decisions/`, `policy/`, and `audit/`.** This is the pure evaluation orchestration layer introduced by ADR-0006. It sequences evaluation stages, invokes `policy/`-owned pure evaluators and combiners, propagates their typed results between stages, and composes the results into bounded decision, trace, response, and kernel audit-evidence artifacts. `evaluation/` does not implement a second copy of policy semantics — if a policy semantic operation is missing, it belongs in `policy/`, not in `evaluation/`. `evaluation/` must not import `adapters/` or `enforcement/`; it sits below both in the graph.

**`adapters/` imports `domain/`, `decisions/`, and `policy/`.** Adapters produce `NormalizedEvent` objects (which reference domain types) and construct `DecisionRequest` objects before submitting them to an enforcement point. The `policy/` permission is architecture-ceiling alignment — adapters may read policy contracts to understand a valid decision request/policy shape — and is intentionally one-way: `adapters` may import `policy`, but `policy` must never import `adapters` (`tests/test_import_boundaries.py::test_policy_does_not_import_from_adapters` protects the reverse direction; no current `basis_core.adapters` module exercises the forward one). Adapters do not import the evaluation layer or audit machinery directly — they submit normalized requests and receive response values. Adapters must not import from `enforcement/`; the application wires adapters to enforcement points, not the library. This section governs the internal `basis_core.adapters` subpackage only; it makes no claim about the external `basis-adapters` repository's implementation responsibilities.

**`enforcement/` may import from all other packages.** The `EnforcementPoint` (and its operation-aware counterpart) in `enforcement/` is the orchestration layer: it connects a `PolicyEngine`/`evaluation/` pipeline, an `AuditWriter` (from `audit/`), and a `DecisionRequest` (from `decisions/`) into a single evaluation path, and owns runtime enforcement and side effects. It is the only layer permitted to call both policy/evaluation and the audit writer in the same execution path. Because `enforcement/` is at the top of the dependency graph, nothing else imports from it — which is what keeps the lower layers independently testable.

## Verifying the boundary

The primary enforcement is in `tests/test_import_boundaries.py`, which uses `ast.parse()` to inspect every kernel source file statically. It asserts:

- No imports from external framework packages (FastAPI, Flask, SQLAlchemy, HTTP clients, etc.)
- No imports from OT protocol libraries, cloud SDKs, or Kubernetes clients
- `domain/` does not import from any other `basis_core` subpackage
- `policy/` does not import from `audit/`, `enforcement/`, or `adapters/`
- `enforcement/` does not import from `adapters/`
- `audit/` does not import from `enforcement/`, `adapters/`, or `policy/`
- `decisions/` does not import from `enforcement/`

The top-level scanners above are non-recursive per subpackage; nested `*/operation_aware/` packages that need the same protection get their own targeted recursive test. `tests/operation_aware/test_vocabulary_boundaries.py` protects `domain/operation_aware_vocabulary.py`, and `tests/test_import_boundaries.py::test_audit_operation_aware_does_not_import_from_policy_enforcement_or_adapters` recursively protects `audit/operation_aware/`. A matching recursive guard for `policy/operation_aware/` does not yet exist and is tracked in `docs/implementation/basis-core-v0.2-operation-aware-plan.md`. A recursive guard for `evaluation/operation_aware/` cannot exist yet — that package is not created by this PR — and is required as part of the PR that first creates it, per the same roadmap document.

`tests/test_import_boundaries.py` asserts no `policy/`-vs-`decisions/` rule at all — that boundary is covered elsewhere. `tests/test_models.py::test_policy_does_not_import_from_decisions` is the legacy-rule test: it scans only `src/basis_core/policy/*.py` non-recursively (`pkg_dir.glob("*.py")`, not `.rglob`), so it covers `policy/engine.py` and `policy/rules.py` and does **not** reach `policy/operation_aware/*.py`. It was written for, and continues to protect exactly, the legacy v0.1 top-level subtree — it does not recursively govern the whole `policy/` package, and this document does not claim otherwise. `tests/test_models.py` and `tests/test_policy_rules.py` also include other targeted static boundary assertions for the packages they exercise. These complement `test_import_boundaries.py` but `test_import_boundaries.py` is the authoritative boundary check for everything except the legacy policy/decisions rule, which `test_models.py` alone covers.

These tests do not require running the imported modules. They catch violations at the source level, before they produce a `CircularImportError` at runtime.

## Architectural context

The layer structure above implements the kernel isolation model defined in `basis-architecture/docs/kernel-boundary-rules.md`, extended by ADR-0006 for the `evaluation/` package. The structural intent:

- `enforcement/` is the **runtime orchestration layer**. It is the only component authorized to compose policy/evaluation, decision handling, audit writing, and side effects into a single execution path. Nothing outside the application layer may import from `basis_core.enforcement` — not other basis_core subpackages, and not external adapter or gateway code.
- `evaluation/` is the **pure evaluation orchestration layer** (ADR-0006). It sequences and invokes `policy/`-owned semantic operations and composes their typed results into decision, trace, response, and bounded kernel audit-evidence artifacts. Unlike `enforcement/`, it performs no side effects, no persistence, and no runtime enforcement — see `docs/kernel-constitution.md` for the full purity invariants this layer must preserve.
- `domain/`, `decisions/`, `policy/`, `audit/`, `evaluation/`, and `adapters/` must each be independently testable without instantiating the enforcement layer. This testability is a kernel property, not a testing convenience.
- **Framework and runtime code must remain outside the kernel entirely.** HTTP frameworks, database ORMs, cloud SDKs, and protocol-specific libraries must not appear in any `basis_core` subpackage. The import boundary tests verify this statically.
- **Protocol-specific packages must remain outside the kernel.** BACnet libraries, Modbus libraries, MQTT clients, and similar must not enter any layer. Protocol normalization belongs in `basis-adapters`, not here.

If a proposed change requires expanding the import boundary rules — relaxing a constraint, permitting a new external dependency, or allowing a new inter-layer dependency — that change should be proposed and reviewed separately before the implementation that depends on it is merged. Import boundary rules are governance infrastructure. Expanding them to accommodate a specific feature is the wrong order of operations.
