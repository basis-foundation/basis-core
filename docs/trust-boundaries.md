# Trust Boundaries

A trust boundary is a defined point where the assumptions about who or what is present, what they are permitted to do, and how that determination is made change between two connected domains. Trust boundaries are architectural facts, not security configurations. They exist where the operational, administrative, and capability properties of two domains differ.

basis-core is positioned at trust boundaries. The library provides what an enforcement point needs to evaluate requests and record decisions at those boundaries.

## Where enforcement belongs

Enforcement belongs at every boundary where:

1. Identity context is available to attach to authorization requests.
2. The operational latency budget accommodates evaluation.
3. Traffic crossing the boundary is observable.

In OT deployments, this typically means the boundary between the supervisory layer and the field device layer (the edge enforcement point) and the boundary between the remote access layer and the OT environment (the jump host or session gateway).

Enforcement does not belong inside time-critical control loops, on devices without the compute resources to evaluate policy, or at points where identity context is unavailable.

## The field device boundary

The transition from the edge enforcement layer to the field device layer is the final authorization boundary before traffic reaches devices that cannot verify it themselves. A BAS controller receiving a write command has no mechanism for confirming that the command passed through an enforcement point. The security property of the field device zone is entirely contingent on the integrity of enforcement applied at the boundary above it.

This is a structural property of existing OT deployments, not a failure of the authorization model. Physical access controls, network segmentation, and maintenance procedure discipline close the gaps the software model cannot.

## Identity propagation

When a request passes through multiple system components before reaching the enforcement point, the original requester's identity must be carried through each hop. If an intermediate component substitutes its own identity for the original subject's, the enforcement point and audit record will attribute the action to the intermediary — not to the principal who initiated it.

basis-core does not enforce identity propagation. It records what it receives. Maintaining the propagation chain is a responsibility of the components between the initial authentication event and the enforcement point.

## Local policy caches

At edge enforcement points with intermittent connectivity to central policy services, local policy caches allow enforcement to continue during connectivity gaps. The local cache holds a time-bounded copy of applicable policy. When the policy service is unreachable, the enforcement point evaluates against the cached copy.

The trade-off: a cache that is valid for hours rather than minutes provides more resilience to extended outages, but also means that policy changes (including credential revocations) may not reach the enforcement point for a longer window. The staleness limit is a deployment-specific parameter, not a library default.

basis-core does not implement a caching layer. The application layer that uses the library is responsible for cache management and for defining the staleness policy that applies to its deployment.

## Failure behavior

When the policy engine encounters an evaluation error, basis-core returns a DENY decision and records the error in the audit trail. The library never silently permits a request when an evaluation fails.

What happens at the enforcement point boundary when the policy service is entirely unavailable (not just returning errors, but unreachable) is an application-level decision. The application must define and test its behavior under this condition explicitly — it cannot be inferred from the library's behavior under error conditions.
