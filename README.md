# basis-core

Authorization foundation for operational systems.

basis-core is a Python library providing the authorization kernel: policy evaluation, decision records, and the audit trail. It is protocol-agnostic, infrastructure-independent, and testable without running services.

## What it is

basis-core is the **authorization kernel** — the isolated core that everything else depends on. It contains only the logic for evaluating authorization requests and recording the results. It knows nothing about transports, databases, identity providers, field protocols, or deployment environments.

Future components built around this kernel:
- **basis-gateway** — HTTP and WebSocket API layer for exposing enforcement to networked services.
- **basis-console** — Operator-facing management interface.
- **Protocol adapters** — BACnet, Modbus, MQTT, OPC-UA normalizers that produce `DecisionRequest` objects.
- **Deployment bundles** — Docker, Kubernetes, cloud-specific packaging.

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
from basis_core.enforcement.enforcement import EnforcementPoint
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
