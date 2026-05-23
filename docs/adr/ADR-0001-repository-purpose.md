# ADR-0001 — Repository Purpose and Relationship to Existing Work

**Status**: Accepted
**Date**: 2026-05-22

## Context

The BASIS project has produced two prior repositories:

- **basis-poc**: A full-stack proof of concept demonstrating identity-aware authorization for building automation systems. It includes FastAPI, Keycloak, SQLite, MQTT, a Modbus TCP adapter, a React frontend, and Docker Compose infrastructure. The PoC validated that the authorization model works end-to-end in a controlled environment.

- **basis-architecture**: Architecture documentation and whitepapers describing the conceptual model, trust boundary analysis, and design principles for identity-aware authorization in OT environments.

The PoC demonstrated that the core authorization logic — the policy engine, the domain types, and the audit model — is sound and does not depend on any of the infrastructure around it. The infrastructure (FastAPI routes, SQLite persistence, Keycloak JWT validation, MQTT topics, Docker Compose) was useful for demonstration but is not part of the authorization logic itself.

There is now a need for a repository that provides the authorization foundation in a form that can be consumed by other systems: tested in isolation, integrated into different deployment topologies, and extended without inheriting the PoC's full infrastructure stack.

## Decision

Create **basis-core** as a Python library providing the authorization boundary independent of any specific transport, storage, identity provider, or deployment infrastructure.

basis-core is not a cleaned-up version of basis-poc. It is a new repository that extracts the authorization concepts from the PoC and expresses them as a standalone library. The PoC's infrastructure choices — FastAPI, Keycloak, SQLite, MQTT, Docker — are not incorporated. They can be added by applications that use the library.

The relationship between the three repositories:

- **basis-architecture** documents the principles and model that inform basis-core's design.
- **basis-poc** demonstrates what a full deployment using this model can look like.
- **basis-core** provides the reusable authorization foundation that both an extended PoC and production deployments can build on.

## Consequences

basis-core will initially lack the end-to-end demonstration capability of the PoC. There is no running system here — only the core authorization logic, its tests, and documentation.

Applications that want to expose this logic over HTTP will need to add a web framework. Applications that want persistent audit storage will need to implement an `AuditWriter` backend. Applications that need MQTT or BACnet adapter logic will need to implement `AdapterBase`.

This is the correct trade-off. A library that bundles its own transport, storage, and identity provider is not a library — it is an application. basis-core stays out of those decisions so that the authorization logic can be used in environments with different constraints.
