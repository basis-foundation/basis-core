# Scope

This document defines what is and is not part of basis-core, and why.

## In scope

**Authorization evaluation.** The policy engine evaluates (subject, resource, action) against defined policy and returns a decision. This is the primary function of the library.

**Decision records.** Structured types for DecisionRequest and DecisionResponse define the contract for submitting authorization requests and interpreting results.

**Audit event types.** The AuditEvent structure and the AuditWriter protocol define what gets recorded and the interface for recording it. Concrete storage backends are out of scope.

**Domain types.** Subject, Resource, and Action provide normalized representations of the authorization primitives. These types are protocol-agnostic; they do not carry BACnet, Modbus, or MQTT-specific fields.

**The Policy protocol and concrete implementations.** RolePolicy provides RBAC-style evaluation. The Policy protocol allows custom implementations to be injected without modifying the engine.

**The Adapter protocol.** AdapterBase defines the lifecycle interface for protocol adapters. It specifies what adapters must implement; it does not implement any protocol.

**The EnforcementPoint.** Connects the policy engine and audit writer into a single evaluation path. It is the component that produces both a decision and an audit record from a single authorization request.

## Out of scope

**HTTP servers and API frameworks.** FastAPI, Starlette, Flask, and similar are not dependencies. Transport is added by the application layer.

**Databases and storage.** The library defines where storage is needed (AuditWriter) and what is stored (AuditEvent), not how it is stored. SQLite, PostgreSQL, append-only files, and log aggregation pipelines are application concerns.

**Identity providers and token issuance.** Keycloak, Dex, and other OIDC providers are not dependencies. Token validation logic belongs in the application layer; the library receives a verified Subject.

**Protocol adapters.** BACnet, Modbus, MQTT, OPC-UA, and other field protocol adapters are not part of this library. They implement the AdapterBase interface and depend on basis-core; they are not contained within it.

**Deployment infrastructure.** Docker, Kubernetes, cloud infrastructure, and container orchestration are not part of the library. Deployment is the responsibility of the application that uses the library.

**Policy authoring tools.** This version provides a Python API for defining policies (via RolePolicy and the Policy protocol). A policy configuration language, a policy administration interface, and policy versioning infrastructure are application concerns.

**Certificate management and credential lifecycle.** PKI, certificate rotation, and device enrollment are out of scope. The library assumes that identity verification has already occurred before a Subject is constructed.

## Scope boundary rationale

The boundary is drawn to keep the library small, testable, and infrastructure-independent. A library that requires a running Keycloak instance, a PostgreSQL database, and a Docker network to test is not a library — it is an application. The core authorization logic must be exercisable in a Python test without any infrastructure.

Features are added to the core when they are needed by the authorization boundary itself. Features that belong in an adapter, a framework, or an application are not added.
