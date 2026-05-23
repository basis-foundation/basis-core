# basis-core

Authorization foundation for operational systems.

basis-core is a Python library providing the authorization boundary: policy evaluation, decision records, and the audit trail. It is protocol-agnostic, infrastructure-independent, and testable without running services.

## What it provides

- **PolicyEngine** — evaluates (subject, resource, action) against a configurable policy chain. Fails closed on uncovered actions.
- **EnforcementPoint** — connects the policy engine and audit writer into a single evaluation path. Every decision produces an audit record.
- **Domain types** — Subject, Resource, Action, IdentityContext. Normalized representations that protocol adapters produce and policy rules consume.
- **AuditEvent / AuditWriter** — structured audit records and the protocol for writing them. Storage backends are provided by the application.
- **AdapterBase / NormalizedEvent** — lifecycle and normalization contracts for protocol adapters. Adapter implementations are out of scope.

## What it does not provide

- An HTTP server or API framework.
- A database or storage backend.
- An identity provider or token validation.
- Protocol adapter implementations (BACnet, Modbus, MQTT, etc.).
- Deployment infrastructure.

These are added by applications that use the library.

## Installation

```
pip install basis-core
```

Requires Python 3.10+. Runtime dependency: [pydantic](https://docs.pydantic.dev/) ≥ 2.0.

## Quick start

```python
from basis_core.api.enforcement import EnforcementPoint
from basis_core.audit.writer import LogAuditWriter
from basis_core.decisions.models import DecisionRequest
from basis_core.domain.subject import Subject
from basis_core.policy.engine import PolicyEngine
from basis_core.policy.rules import RolePolicyRule

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

## Repository context

- **basis-architecture** — architecture principles and trust boundary analysis that inform this library's design.
- **basis-poc** — a full-stack proof of concept demonstrating this authorization model in a building automation context.

## License

MIT
