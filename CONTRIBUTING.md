# Contributing to basis-core

basis-core is an implementation repository, not an ecosystem governance repository. Architectural constraints, terminology requirements, compatibility philosophy, and kernel boundary rules are defined in the [basis-architecture](https://github.com/basis-foundation/basis-architecture) repository. This guide describes what that means for contributors.

---

## Before proposing kernel changes

Read the following documents in basis-architecture before proposing changes that affect authorization semantics, the enforcement boundary, audit schema, import structure, or action vocabulary:

- `docs/kernel-boundary-rules.md` — enforceable rules for what may and may not enter basis-core; the primary review reference
- `docs/architecture/basis-ecosystem.md` — component responsibilities, dependency direction, what belongs in basis-core and what must stay outside it
- `docs/architecture/compatibility-philosophy.md` — compatibility commitments for action names, audit schemas, adapter normalization, and policy evaluation semantics
- `docs/architecture/action-vocabulary.md` — action naming governance and stability expectations
- `docs/standards/terminology-rules.md` — required terminology and prohibited synonyms

A proposed change that is technically functional may still be rejected if it violates kernel boundary rules, compatibility philosophy, import boundary constraints, or terminology requirements. These are not style preferences — they are architectural invariants.

---

## Kernel boundary discipline

basis-core is the isolated authorization kernel. It must remain:

- **Protocol-agnostic.** No knowledge of BACnet, Modbus, MQTT, OPC-UA, or any other field or application protocol may enter the kernel.
- **Transport-agnostic.** No HTTP, WebSocket, gRPC, AMQP, or other transport-layer code.
- **Free of network I/O during evaluation.** Policy evaluation must be synchronous and in-process. A given subject, resource, action, and policy set must produce the same decision on every evaluation with no dependence on external runtime state.
- **Free of framework and runtime coupling.** No FastAPI, Flask, SQLAlchemy, database clients, Kubernetes client libraries, cloud SDK dependencies, or identity provider clients.
- **Free of dependency creep.** Adding a new dependency to `pyproject.toml` requires justification. The kernel's minimal dependency footprint is a deliberate design property.

If a proposed feature requires relaxing any of these constraints, the correct starting point is an architectural discussion in basis-architecture, not a pull request to this repository.

See `docs/kernel-boundary.md` and `docs/import-boundaries.md` in this repository for implementation-level detail. See `docs/scope.md` for the explicit scope boundary and rationale.

---

## Compatibility discipline

Certain artifacts in basis-core are compatibility surfaces — once established, they must not be changed without a versioned, documented break and a defined deprecation period:

- **Action names** are contracts. They appear in deployed policies and audit records simultaneously. Renaming an established action produces silent policy failures and audit discontinuity. See `docs/core-domain.md` and `basis-architecture/docs/architecture/action-vocabulary.md`.
- **Resource identifier formats** are audit contracts. The `{type}:{qualifier}` format is a compatibility surface. Changing the format invalidates policy references and breaks audit correlation. See `docs/core-domain.md`.
- **Audit event fields** are immutability contracts. Required fields must not be removed or renamed. Schema changes must be additive. New required fields constitute a breaking change unless backfillable. See `docs/audit-model.md`.
- **Adapter normalization changes** produce silent policy and audit divergence. Normalization changes must be documented and versioned. See `docs/adapter-contracts.md`.
- **Policy evaluation semantics** must be stable across kernel version increments. Changing the evaluation behavior of an existing policy construct is a breaking change. See `docs/policy-model.md`.

---

## Terminology consistency

Use the terms defined in `basis-architecture/docs/standards/terminology-rules.md`. In particular:

| Term | Notes |
|---|---|
| **authorization kernel** | The correct description of what basis-core is |
| **enforcement boundary** / **enforcement point** | The component that applies authorization decisions to operational traffic |
| **policy engine** | The component that evaluates authorization requests against policy |
| **adapter normalization** | The process by which adapters translate protocol-specific operations into the shared vocabulary |
| **audit event** | A structured record of an authorization decision |
| **DecisionRequest** / **DecisionResponse** | The request and response types at the enforcement boundary |
| **basis-core** | Always lowercase; not "Basis Core", "BasisCore", or "the kernel service" |
| **basis-architecture** | The governance repository; not interchangeable with "the architecture" generically |

Do not introduce synonyms for established terms. If an existing term is awkward in a specific context, rephrase the sentence rather than coining an alternative.

---

## Import boundary discipline

The subpackage dependency graph within basis-core enforces strict layer separation. Lower layers must not import from higher layers:

```
enforcement/  ← orchestration layer; nothing else in basis_core imports from this
adapters/     ← may import: domain/, decisions/
audit/        ← may import: domain/
policy/       ← may import: domain/
decisions/    ← may import: domain/
domain/       ← imports nothing from within basis_core
```

`enforcement/` is the only layer that may compose policy evaluation and audit writing in a single execution path. Nothing outside the application layer may import from `basis_core.enforcement`.

Framework and runtime code (HTTP clients, database ORMs, cloud SDKs, protocol stacks) must not appear in any basis_core subpackage. The import boundary tests in `tests/test_import_boundaries.py` enforce this statically.

Proposed changes to the import boundary structure should be proposed and reviewed separately before the implementation changes that depend on them. Import boundary rules are governance infrastructure, not incidental test coverage.

See `docs/import-boundaries.md` for the full specification. The architectural intent is stated in `basis-architecture/docs/kernel-boundary-rules.md`.

---

## Implementation vs. architecture

basis-architecture defines semantics and constraints. basis-core realizes those semantics in executable form. Implementation details — data structure choices, internal algorithm design, Python version targeting — may evolve while preserving the architectural invariants.

When an implementation reveals that an architectural constraint is impractical, the correct response is to raise the conflict in basis-architecture rather than resolving it silently here. The architecture may need refinement; that refinement should be deliberate and visible.

basis-poc is a research proof-of-concept that validated the core mechanisms. It is not the canonical implementation reference and should not be cited as the reason a particular implementation choice was made.

---

## Development workflow

Install with dev dependencies:

```bash
pip install -e ".[dev]"
```

All of the following must pass before a pull request can be accepted:

```bash
pytest
ruff check src tests
ruff format --check src tests
mypy src
```

These checks correspond to the required implementation checks stated in `basis-architecture/docs/kernel-boundary-rules.md`.
