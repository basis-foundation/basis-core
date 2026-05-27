# basis-core

Authorization foundation for operational systems.

basis-core is a Python library providing the authorization kernel: policy evaluation, decision records, and the audit trail. It is protocol-agnostic, infrastructure-independent, and testable without running services.

## What it is

basis-core is the **authorization kernel** — the isolated core that everything else depends on. It contains only the logic for evaluating authorization requests and recording the results. It knows nothing about transports, databases, identity providers, field protocols, or deployment environments.

Components built around this kernel:
- **basis-gateway** — API and runtime wrapper; hosts the HTTP interface, invokes basis-core for evaluation, acts as the enforcement point for networked services.
- **basis-console** — Operator and administrator UI; contains no authorization logic.
- **basis-adapters** — Protocol normalization adapters; translates BACnet, Modbus, MQTT, OPC-UA, and other field-protocol messages into the subject-resource-action vocabulary basis-core evaluates.
- **basis-deploy** — Deployment and distribution tooling; not part of the authorization runtime.

None of these belong in this repository. basis-core must remain free of those dependencies so it can be embedded, tested, and reasoned about independently.

## What it provides

- **PolicyEngine** — evaluates (subject, resource, action) against a configurable policy chain. Fails closed on uncovered actions.
- **EnforcementPoint** — connects the policy engine and audit writer into a single evaluation path. Every decision produces an audit record. Fail-closed on all error paths.
- **Domain types** — Subject, Resource, Action, IdentityContext. Normalized representations that protocol adapters produce and policy rules consume.
- **AuditEvent / AuditWriter** — structured audit records and the protocol for writing them. Storage backends are provided by the application.
- **AdapterBase / NormalizedEvent** — lifecycle and normalization contracts for protocol adapters. Adapter implementations live outside this repo.

## What it does not provide

- An HTTP server or API framework.
- A database or storage backend.
- An identity provider or token validation.
- Protocol adapter implementations (BACnet, Modbus, MQTT, etc.).
- Deployment infrastructure.

These are added by applications and services that use the library.

## Installation

```
pip install basis-core
```

Requires Python 3.10+. Runtime dependency: [pydantic](https://docs.pydantic.dev/) ≥ 2.0.

## Quick start

```python
from basis_core.enforcement import EnforcementPoint
from basis_core.audit import LogAuditWriter
from basis_core.decisions import DecisionRequest
from basis_core.domain import Subject
from basis_core.policy import PolicyEngine, RolePolicyRule

ROLE_TABLE = {
    "write:hvac:setpoint": {"operator", "admin"},
    "read:audit:log":      {"admin"},
}

engine = PolicyEngine(policies=[RolePolicyRule(ROLE_TABLE)])
ep = EnforcementPoint(engine=engine, audit_writer=LogAuditWriter())

subject = Subject(id="u1", name="alice", roles=["operator"])
request = DecisionRequest(
    subject_id=subject.id,
    subject_roles=subject.roles,
    resource_id="hvac:zone-a",
    action="write:hvac:setpoint",
)

response = ep.evaluate(request, subject=subject)
print(response.outcome)   # DecisionOutcome.ALLOW
```

See `examples/basic_evaluation.py` for a more complete example.

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Format check (matches CI)
ruff format --check src tests

# Lint
ruff check src tests

# Type check
mypy src
```

## Ecosystem and architectural authority

basis-core implements the authorization kernel defined by the [basis-architecture](https://github.com/basis-foundation/basis-architecture) repository. Architecture constraints, compatibility commitments, kernel boundary rules, and required terminology originate there. This repository realizes those constraints in executable form.

The BASIS Core Services Distribution places basis-core at the foundation of a layered component hierarchy:

| Component | Role |
|---|---|
| **basis-core** (this repository) | Authorization kernel — policy evaluation, enforcement semantics, failure mode contracts, audit event schema |
| **basis-gateway** | API and runtime wrapper — request lifecycle, decision dispatch, enforcement point for networked services |
| **basis-console** | Operator and administrator UI — no authorization logic |
| **basis-adapters** | Protocol normalization adapters — translates field-protocol messages into normalized vocabulary |
| **basis-deploy** | Deployment and distribution tooling — not part of the authorization runtime |
| **basis-poc** | Research proof-of-concept — validated the core mechanisms; a research artifact, not the canonical implementation |

Dependency direction is strictly downward: every component in the distribution depends on basis-core; basis-core must not depend on any of them.

The basis-architecture repository is the review authority for changes that affect kernel boundaries, action vocabulary, audit schema compatibility, or terminology. When an implementation constraint conflicts with an architectural rule defined in basis-architecture, surface the conflict there rather than resolving it silently in this repository.

See `docs/architecture-references.md` in this repository for a map of implementation concepts to the relevant basis-architecture documents.

## License

MIT
