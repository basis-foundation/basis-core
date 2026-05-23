# ADR-0004 — Protocol Adapters Are Outside the Core

**Status**: Accepted
**Date**: 2026-05-22

## Context

The basis-poc demonstrated that the authorization model is protocol-agnostic. The PoC integrated MQTT telemetry and a Modbus TCP adapter without modifying the policy engine, audit logger, or domain types. The `AdapterBase` interface proved sufficient: two lifecycle methods and two identifying attributes. Adding the Modbus adapter required one new action constant, one new RBAC table entry, and one `AdapterBase` implementation — no changes to any security-path code.

The question for basis-core is whether protocol adapter implementations should be included in the core library or kept separate.

Arguments for including adapters in the core:
- Convenience: consumers get a working adapter when they install the library.
- Consistency: adapter implementations are developed alongside the interfaces they implement.

Arguments for keeping adapters separate:
- Dependency isolation: a BACnet adapter requires a BACnet library. A Modbus adapter requires a Modbus library. These are large, platform-specific dependencies that should not be forced on consumers who do not use those protocols.
- Scope discipline: the core boundary (ADR-0003) is authorization logic. Protocol normalization is not authorization logic. The adapter transforms a protocol message into a normalized request; it does not evaluate whether the request is permitted.
- Stability: adapter implementations change more frequently than the authorization model. Protocol-specific normalization depends on device firmware versions, register map updates, and vendor-specific behavior. These concerns should not destabilize the core library.
- Testability: the core library tests must not require a running Modbus device, a BACnet/IP network, or an MQTT broker.

## Decision

Protocol adapter implementations are not part of basis-core. The library provides only the `AdapterBase` protocol and `NormalizedEvent` type in `basis_core.adapters.base`. These define what adapters must implement; they impose no dependencies.

Concrete adapter implementations (for BACnet, Modbus, MQTT, OPC-UA, etc.) belong in separate packages or repositories. They depend on basis-core; basis-core does not depend on them.

The `AdapterBase` protocol and `NormalizedEvent` type are stable interfaces. They are part of the core boundary and will not change without a versioned, documented update to this ADR.

## Consequences

There are no working adapters included in this repository. The `examples/` directory contains an example that constructs `DecisionRequest` objects directly (simulating what an adapter would do), but not a real protocol adapter.

The separation means that an integration test covering the full path from a BACnet write to an audit record cannot be run in this repository alone. That integration test belongs in the adapter repository or in an application that assembles both.

The `AdapterBase` interface is intentionally minimal. If integration experience reveals that a richer interface would benefit adapter authors (health check hooks, subscription management, error reporting), that is a candidate for a future revision. Premature richness creates compatibility obligations before there is evidence it is needed.
