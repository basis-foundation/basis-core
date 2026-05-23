# Vision

basis-core is a Python library that provides the authorization boundary for operational systems.

The core function is straightforward: given a subject, a resource, and an action, evaluate whether the action is permitted and record the decision. Every other concern — what transport delivered the request, what protocol the resource speaks, where audit records are stored — is handled outside the core.

## What problem this addresses

Operational environments — building automation systems, industrial control infrastructure, facility management — are increasingly interconnected with enterprise networks, remote access services, and third-party integrations. The network boundaries that historically provided implicit trust have eroded. In many deployments, there is no systematic answer to the question: who is permitted to do what to which device, under what conditions, and how do we know what was actually done?

basis-core provides a foundation for answering that question. It is not a complete product. It is a library that can be integrated into the systems that enforce and audit access to operational infrastructure.

## What this is not

This library is not a network security tool. It does not inspect packets, manage firewalls, or detect intrusions. It evaluates authorization requests that have already been constructed from verified identity context.

This library is not a complete authorization service. It does not include an HTTP server, a database, an identity provider, or a deployment platform. Those are added by the application layer that consumes the library.

This library is not a replacement for physical access controls, network segmentation, or device-level security measures. It is one layer in a broader security architecture, not a substitute for the others.

## Design commitments

**The authorization boundary is the product.** The policy engine, the enforcement point, and the audit writer exist to ensure that every decision is evaluated against defined policy and every decision is recorded. These three components are the core of the library. Everything else serves them.

**Adapters normalize; core evaluates.** Protocol-specific logic belongs in adapters. The policy engine and enforcement point reason about normalized subjects, resources, and actions. They do not interpret BACnet object identifiers, Modbus register addresses, or MQTT topic strings.

**Operational continuity matters.** A system that becomes unavailable in the same conditions that require rapid operator response is not safe infrastructure. The library is designed so that local caches and fail-safe behaviors can be implemented at the application layer without architectural compromise.

**Keep it small and understandable.** A library that is difficult to reason about is difficult to trust. The scope of this library is constrained deliberately. Features that belong in an adapter, a framework, or an application are not added to the core.
