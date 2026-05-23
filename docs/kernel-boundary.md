# Kernel Boundary

## What this repository is

basis-core is the **authorization kernel** — the isolated core that all other components depend on. It contains exactly the logic needed to evaluate authorization requests and record decisions. Nothing more.

The kernel is designed to be embedded in any application or service that needs authorization. It does not know what transport delivers a request, what database stores the audit log, which identity provider authenticated the user, or which OT protocol the field device speaks. Those concerns belong in the layers around the kernel, not inside it.

## What the kernel contains

```
basis_core/
  domain/       Subject, Resource, Action, IdentityContext — shared vocabulary
  decisions/    DecisionRequest, DecisionResponse, FailureReason — boundary contracts
  policy/       PolicyEngine, PolicyRule, Decision — evaluation logic
  audit/        AuditEvent, AuditWriter, DecisionTrace — accountability records
  enforcement/  EnforcementPoint — orchestrates policy + audit in one path
  adapters/     AdapterBase, NormalizedEvent — contracts for protocol normalization
```

Each of these is a kernel concern. The kernel enforces import discipline across these packages: lower layers do not import from higher layers. See `docs/import-boundaries.md`.

## What the kernel does not contain

The following concerns are intentionally out of scope for this repository:

**Transports.** HTTP routing, WebSocket servers, MQTT subscriptions, BACnet/IP listeners — these are transport concerns. A transport layer receives a request in its native protocol, normalizes it to a `DecisionRequest`, calls an `EnforcementPoint`, and dispatches the result. The kernel provides the enforcement boundary; the transport provides the delivery mechanism.

**Persistence.** The `AuditWriter` protocol defines how audit events are delivered. The kernel ships a `LogAuditWriter` for development. Production persistence — append-only file writers, time-series database connectors, SIEM integrations — belong in the application layer or a dedicated audit service.

**Identity provider integration.** The kernel accepts a `Subject` or a `DecisionRequest` with `subject_id` and `subject_roles`. How those fields were verified — JWT validation, LDAP lookup, certificate inspection — happens before the enforcement boundary. The kernel does not call Keycloak, LDAP, Active Directory, or any external identity system.

**Protocol adapter implementations.** `AdapterBase` and `NormalizedEvent` are the contracts; they live in the kernel because the kernel defines what an adapter must produce. Actual adapter code — BACnet, Modbus, MQTT, OPC-UA — belongs in protocol-specific repositories or a shared adapter library, not here.

**Operator interface.** No dashboards, no configuration UI, no management console. Those belong in a future `basis-console` component.

**Deployment packaging.** No Docker files, no Kubernetes manifests, no cloud-provider configuration. Those belong in deployment-specific repositories.

## Future components built around the kernel

```
basis-core          ← this repository: the authorization kernel
    ↑
basis-gateway       HTTP/WebSocket API layer (future)
    ↑
basis-console       Operator management interface (future)

protocol adapters   BACnet, Modbus, MQTT normalizers (future, separate repos)

deployment bundles  Docker, Kubernetes, cloud-specific packaging (future)
```

The dependency arrow points inward: every component above depends on `basis-core`, but `basis-core` depends on none of them. This is the defining structural constraint of the kernel architecture.

## Why this boundary matters

**Testability.** The kernel can be tested completely in-process, without running any external service. Every test in this repository runs without network access, without a database, and without a running identity provider.

**Embeddability.** Any application that needs authorization — a gateway, an adapter host, an operator console — can import and use the kernel directly. It does not carry framework or infrastructure dependencies that would conflict with the host application's stack.

**Auditability.** A kernel with a narrow, stable interface is easier to audit for security properties. A kernel that imports an HTTP framework, a database ORM, and an identity SDK is harder to reason about, harder to test, and harder to change safely.

**Replaceability.** The gateway, console, and adapters are not monolithic. New transport implementations can be added without changing the kernel. New policy rule types can be added without changing the transport layer. The kernel's clean boundary makes each component independently replaceable.

## Checking the boundary

The kernel boundary is enforced by tests in `tests/test_import_boundaries.py`. These tests use `ast.parse()` to inspect source files statically and confirm that no kernel package imports from frameworks, infrastructure libraries, or protocol-specific packages.

Run them with:

```bash
pytest tests/test_import_boundaries.py -v
```

Any import of FastAPI, Flask, SQLAlchemy, MQTT libraries, BACnet libraries, or Kubernetes SDKs in the kernel source will fail these tests.
