# Import Boundaries

This document defines the allowed dependency direction between `basis_core` subpackages. The rule is simple: lower layers do not import from higher layers. `domain/` has no `basis_core` imports at all. `api/` may import from everything else, but nothing imports from `api/`.

Violations of these boundaries are bugs, not style issues. A module that imports from a layer above it introduces a circular dependency risk and erodes the testability of the lower layer.

## Allowed dependencies

```
api/
  ├── may import from: policy/, audit/, decisions/, adapters/, domain/
  └── must not be imported by: any other basis_core subpackage

adapters/
  ├── may import from: decisions/, domain/
  └── must not import from: policy/, audit/, api/

audit/
  ├── may import from: decisions/, domain/
  └── must not import from: policy/, adapters/, api/

policy/
  ├── may import from: domain/
  └── must not import from: decisions/, audit/, adapters/, api/

decisions/
  ├── may import from: domain/
  └── must not import from: policy/, audit/, adapters/, api/

domain/
  ├── may import from: (nothing in basis_core)
  └── must not import from: any other basis_core subpackage
```

As a directed graph, the only permitted edges are:

```
domain/ ← decisions/ ← audit/
                     ← adapters/
        ← policy/
        ← api/ → policy/ → decisions/ → domain/
              → audit/    ↑
              → adapters/ ↑
              → decisions/↑
```

## Rationale for each constraint

**`domain/` has no basis_core imports.** Domain types are the shared vocabulary of the entire library. If `domain/` imported from `policy/` or `decisions/`, those packages could not safely import from `domain/` without creating a cycle. The domain layer must remain a dependency sink.

**`policy/` imports only `domain/`.** The policy engine reasons about subjects, resources, and actions — all defined in `domain/`. It does not need to know about the DecisionRequest/Response envelope (`decisions/`), audit plumbing (`audit/`), or transport (`api/`). Keeping `policy/` narrow means it can be tested in complete isolation: construct a `Subject`, call `evaluate()`, check the `Decision`. No other packages need to be loaded.

**`decisions/` imports only `domain/`.** `DecisionRequest` and `DecisionResponse` are the data contract at the enforcement boundary. They reference domain types (via field names and string identifiers) but do not import the policy engine or audit machinery. This keeps the contract types lightweight and independently usable.

**`audit/` imports `domain/` and `decisions/`.** `AuditEvent` records the full context of a decision: subject fields (from `domain/`), action, resource, outcome, and the `request_id` that correlates it with a `DecisionRequest` (from `decisions/`). The audit layer does not need to import the policy engine or the API layer.

**`adapters/` imports `domain/` and `decisions/`.** Adapters produce `NormalizedEvent` objects (which reference domain types) and construct `DecisionRequest` objects before submitting them to an enforcement point. They do not import the policy engine directly — they submit normalized requests and receive `DecisionResponse` values. Adapters must not import from `api/`; the application wires adapters to enforcement points, not the library.

**`api/` may import from all other packages.** The `EnforcementPoint` in `api/` is the orchestration layer: it connects a `PolicyEngine` (from `policy/`), an `AuditWriter` (from `audit/`), and a `DecisionRequest` (from `decisions/`) into a single evaluation path. It is the only layer permitted to call both the policy engine and the audit writer in the same execution path. Because `api/` is at the top of the dependency graph, nothing else imports from it — which is what keeps the lower layers independently testable.

## Verifying the boundary

The import boundary is tested in `tests/test_import_boundaries.py`. The test uses `ast.parse()` to inspect each source file statically and confirm that no module below `api/` contains an import from `basis_core.api`.

This test does not require running the imported modules. It catches violations at the source level, before they produce a `CircularImportError` at runtime — which may only surface under specific import orderings and is harder to diagnose.
