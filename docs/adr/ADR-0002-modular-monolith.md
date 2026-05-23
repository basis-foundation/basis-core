# ADR-0002 — Modular Monolith Package Structure

**Status**: Accepted
**Date**: 2026-05-22

## Context

The authorization logic has several distinct concerns: domain types, policy evaluation, decision records, audit events, adapter contracts, and the enforcement point that connects them. These concerns could be structured in different ways.

One option is a flat module structure, where all types and functions live in a small number of files. This is simple for small codebases but makes it difficult to reason about dependencies and import direction as the library grows.

Another option is separate installable packages (one for domain types, one for the policy engine, one for adapters, etc.). This would allow consuming applications to install only what they need. But it introduces coordination overhead: version alignment across packages, inter-package API contracts that must be maintained, and release workflows that are complex relative to the size of the codebase at this stage.

A third option, drawn from the PoC (ADR-0001 in basis-poc), is a modular monolith: a single installable package (`basis_core`) with clear internal module boundaries that prevent circular imports and allow the library's structure to be understood from the package layout.

## Decision

Structure basis-core as a modular monolith with enforced import direction.

The package layout reflects the authorization architecture:

```
basis_core/
  domain/       — canonical types. No basis_core imports.
  policy/       — policy engine. Imports from domain/ only.
  decisions/    — decision request/response. Imports from domain/ only.
  audit/        — audit events and writer protocol. Imports from domain/ and decisions/.
  adapters/     — adapter protocol. Imports from domain/ and decisions/.
  api/          — enforcement point and transport entry points. May import from all above.
```

The import direction is one-way: lower layers do not import from higher layers. `domain/` has no `basis_core` imports at all. `api/` may import from everything else, but nothing imports from `api/`. This constraint is enforced by convention and verified through import order inspection in code review.

The import graph is:

```
api/ → adapters/, audit/, decisions/, policy/, domain/
adapters/ → domain/, decisions/
audit/ → domain/, decisions/
policy/ → domain/
decisions/ → domain/
domain/ → (nothing in basis_core)
```

## Consequences

All library components are installed together. An application that only needs the domain types and policy engine still installs the audit and adapter modules. For a library of this size, this is not a meaningful burden.

The clear module boundaries mean that the authorization logic can be tested layer by layer: domain types with no dependencies, the policy engine with domain types, the enforcement point with both. This is more valuable than install-time isolation for the current scope.

If the library grows substantially, individual subpackages can be extracted as separate installable distributions without a structural rewrite. The module boundaries already exist; extraction would be a packaging change, not an architectural one.
