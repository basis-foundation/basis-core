# Import Boundaries

This document defines the allowed dependency direction between `basis_core` subpackages and the constraints on what may enter the kernel at all. It is the implementation specification for the architectural requirements stated in `docs/kernel-boundary-rules.md` in basis-architecture. That document is the architectural authority; this document is the implementation detail.

The rule is simple: lower layers do not import from higher layers. `domain/` has no `basis_core` imports at all. `enforcement/` may import from everything else, but nothing within `basis_core` imports from `enforcement/`.

Violations of these boundaries are bugs, not style issues. A module that imports from a layer above it introduces a circular dependency risk and erodes the testability of the lower layer. A module that imports a framework, database client, or protocol library violates the kernel isolation that makes basis-core embeddable, testable, and portable.

## Allowed dependencies

```
enforcement/
  ├── may import from: policy/, audit/, decisions/, adapters/, domain/
  └── must not be imported by: any other basis_core subpackage

adapters/
  ├── may import from: decisions/, domain/
  └── must not import from: policy/, audit/, enforcement/

audit/
  ├── may import from: domain/
  └── must not import from: policy/, adapters/, enforcement/

policy/
  ├── may import from: domain/
  └── must not import from: decisions/, audit/, adapters/, enforcement/

decisions/
  ├── may import from: domain/
  └── must not import from: policy/, audit/, adapters/, enforcement/

domain/
  ├── may import from: (nothing in basis_core)
  └── must not import from: any other basis_core subpackage
```

As a directed graph, the only permitted edges are:

```
domain/ ← decisions/ ← audit/
                     ← adapters/
        ← policy/
        ← enforcement/ → policy/ → decisions/ → domain/
                       → audit/
                       → adapters/
                       → decisions/
```

## Rationale for each constraint

**`domain/` has no basis_core imports.** Domain types are the shared vocabulary of the entire library. If `domain/` imported from `policy/` or `decisions/`, those packages could not safely import from `domain/` without creating a cycle. The domain layer must remain a dependency sink.

**`policy/` imports only `domain/`.** The policy engine reasons about subjects, resources, and actions — all defined in `domain/`. It does not need to know about the DecisionRequest/Response envelope (`decisions/`), audit plumbing (`audit/`), or enforcement orchestration (`enforcement/`). Keeping `policy/` narrow means it can be tested in complete isolation: construct a `Subject`, call `evaluate()`, check the `Decision`. No other packages need to be loaded.

**`decisions/` imports only `domain/`.** `DecisionRequest` and `DecisionResponse` are the data contract at the enforcement boundary. They reference domain types (via field names and string identifiers) but do not import the policy engine or audit machinery. This keeps the contract types lightweight and independently usable.

**`audit/` imports `domain/` only.** `AuditEvent` records the full context of a decision: subject fields (from `domain/`), action, resource, and outcome. The audit layer does not need to import the policy engine or the enforcement orchestration layer.

**`adapters/` imports `domain/` and `decisions/`.** Adapters produce `NormalizedEvent` objects (which reference domain types) and construct `DecisionRequest` objects before submitting them to an enforcement point. They do not import the policy engine directly — they submit normalized requests and receive `DecisionResponse` values. Adapters must not import from `enforcement/`; the application wires adapters to enforcement points, not the library.

**`enforcement/` may import from all other packages.** The `EnforcementPoint` in `enforcement/` is the orchestration layer: it connects a `PolicyEngine` (from `policy/`), an `AuditWriter` (from `audit/`), and a `DecisionRequest` (from `decisions/`) into a single evaluation path. It is the only layer permitted to call both the policy engine and the audit writer in the same execution path. Because `enforcement/` is at the top of the dependency graph, nothing else imports from it — which is what keeps the lower layers independently testable.

## Verifying the boundary

The import boundary is tested in `tests/test_models.py` and `tests/test_policy_rules.py`. The tests use `ast.parse()` to inspect each source file statically and confirm that modules in `domain/`, `policy/`, `decisions/`, `audit/`, and `adapters/` do not import from `basis_core.enforcement`.

Additional boundary assertions in `tests/test_import_boundaries.py` cover:
- No imports from external framework packages (FastAPI, Flask, SQLAlchemy, etc.)
- `enforcement/` does not import from `adapters/`
- `policy/` does not import from `audit/`, `enforcement/`, or `adapters/`
- `domain/` does not import from any other `basis_core` subpackage

These tests do not require running the imported modules. They catch violations at the source level, before they produce a `CircularImportError` at runtime.

## Architectural context

The layer structure above implements the kernel isolation model defined in `basis-architecture/docs/kernel-boundary-rules.md`. The structural intent:

- `enforcement/` is the **orchestration layer**. It is the only component authorized to compose policy evaluation, decision handling, and audit writing into a single execution path. Nothing outside the application layer may import from `basis_core.enforcement` — not other basis_core subpackages, and not external adapter or gateway code.
- `domain/`, `decisions/`, `policy/`, `audit/`, and `adapters/` must each be independently testable without instantiating the enforcement layer. This testability is a kernel property, not a testing convenience.
- **Framework and runtime code must remain outside the kernel entirely.** HTTP frameworks, database ORMs, cloud SDKs, and protocol-specific libraries must not appear in any `basis_core` subpackage. The import boundary tests verify this statically.
- **Protocol-specific packages must remain outside the kernel.** BACnet libraries, Modbus libraries, MQTT clients, and similar must not enter any layer. Protocol normalization belongs in `basis-adapters`, not here.

If a proposed change requires expanding the import boundary rules — relaxing a constraint, permitting a new external dependency, or allowing a new inter-layer dependency — that change should be proposed and reviewed separately before the implementation that depends on it is merged. Import boundary rules are governance infrastructure. Expanding them to accommodate a specific feature is the wrong order of operations.
