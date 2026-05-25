# Architecture References

This document maps basis-core implementation concepts to the authoritative architecture documents in the [basis-architecture](https://github.com/basis-foundation/basis-architecture) repository. It is the starting point for contributors who need to understand which architectural documents govern a particular area of this codebase.

basis-architecture is the constitutional and semantic authority for the BASIS ecosystem. basis-core implements the authorization kernel defined there. When implementation and architecture conflict, basis-architecture governs.

---

## Ecosystem structure

**Document:** `docs/architecture/basis-ecosystem.md` in basis-architecture

**Governs:** Component responsibilities, dependency direction, and boundary definitions for the entire BASIS ecosystem.

**Why it matters for basis-core contributors:** This document defines exactly what belongs in basis-core and what must stay outside it. It is the canonical source for understanding why basis-core must not contain API hosting, protocol adapter implementations, identity provider clients, or deployment infrastructure — and which components own those concerns instead.

**Relevant for:** Any change that expands the scope of what basis-core does or depends on.

---

## Kernel boundary rules

**Document:** `docs/kernel-boundary-rules.md` in basis-architecture

**Governs:** The enforceable rules that protect basis-core as an isolated authorization kernel. Defines what may enter the kernel, what must stay outside it, and how boundary questions are evaluated.

**Why it matters:** The kernel boundary rules are not preferences — they are invariants. A change that violates any of them requires an ADR and Foundation review before it can be accepted. This document is the primary review reference for any proposed change to basis-core.

**Relevant for:** Any change to a subpackage within `src/basis_core/`, changes to `pyproject.toml` dependencies, or changes to import structure.

**Implementation references:** `docs/kernel-boundary.md` and `docs/import-boundaries.md` in this repository provide the implementation-level detail. The basis-architecture document establishes the architectural intent that those implementation documents realize.

---

## Compatibility philosophy

**Document:** `docs/architecture/compatibility-philosophy.md` in basis-architecture

**Governs:** Why certain artifacts — action names, resource identifiers, audit schemas, policy evaluation semantics, adapter normalization contracts — are durable compatibility commitments rather than subject to casual revision.

**Why it matters:** In OT deployments, components update at different speeds, audit records are retained for years, and policies may remain in effect for the operational lifetime of the controlled systems. Changes to compatibility surfaces must be treated as breaking changes: explicitly versioned, documented, and accompanied by a deprecation period.

**Relevant for:** Changes to `src/basis_core/domain/action.py` (action names), `src/basis_core/audit/` (audit schema), `src/basis_core/decisions/` (decision contracts), `src/basis_core/policy/` (evaluation semantics), and any change to normalization contracts in `docs/adapter-contracts.md`.

---

## Action vocabulary governance

**Document:** `docs/architecture/action-vocabulary.md` in basis-architecture

**Governs:** The naming structure, conventions, and stability expectations for action names used in policy evaluation and audit records. Defines the allowed verb set (`read`, `write`, `command`, `subscribe`, `configure`, `audit`, `enroll`, `revoke`), domain naming rules, and the deprecation process for established names.

**Why it matters:** Action names are contracts, not labels. They appear simultaneously in deployed policies and in audit records. Renaming an established action produces silent policy failures and audit discontinuity without any runtime signal. Action names must be treated with long-term stability expectations from the point of first use in any deployed policy, persisted audit record, or production adapter normalization mapping.

**Relevant for:** Any change to action names used in `src/basis_core/domain/action.py`, test fixtures, or examples that introduce new action names. New action names should follow the `{verb}:{domain}[:{object}]` structure and use only recognized verbs.

---

## Terminology rules

**Document:** `docs/standards/terminology-rules.md` in basis-architecture

**Governs:** The required vocabulary for all BASIS ecosystem repositories. Defines canonical terms, prohibited synonyms, capitalization rules, and the process for introducing new terms.

**Why it matters:** Consistent terminology prevents vocabulary drift that causes contributor confusion and architectural miscommunication. Implementation repositories are explicitly required to align with the canonical vocabulary defined in basis-architecture. When this repository's documentation diverges from the canonical vocabulary, it should be updated to align.

**Relevant for:** All documentation and public API surface naming in this repository. The terminology section in `CONTRIBUTING.md` summarizes the most relevant rules.

---

## Reference architecture vs. implementation

**Document:** `docs/architecture/reference-vs-implementation.md` in basis-architecture

**Governs:** The distinction between conceptual architecture (what must be true), the reference architecture (the BASIS Core Services Distribution as a specific realization), and implementation (what has actually been built).

**Why it matters for basis-core:**

- basis-architecture defines semantics and constraints; basis-core realizes them in executable form. Implementation details — data structure choices, algorithm design, Python version targeting — may evolve while preserving the architectural invariants.
- basis-poc is a research artifact that validated the core mechanisms. It is not the canonical implementation reference. PoC implementation choices do not establish precedent for basis-core design decisions.
- When an implementation constraint conflicts with an architectural requirement, the conflict belongs in basis-architecture as a discussion, not resolved silently in this repository.

**Relevant for:** Understanding the authority of any given basis-architecture document over basis-core implementation decisions, and understanding what distinguishes an architectural requirement from an implementation preference.

---

## Architecture principles

**Document:** `docs/architecture-principles.md` in basis-architecture

**Governs:** The foundational principles motivating the kernel design, including: Protocol Evaluation Independent of Protocol (Principle 5), Operational Resilience First (Principle 6), Protocol Abstraction Where Feasible (Principle 10), Security Must Respect Operational Constraints (Principle 12), and Immutable Security-Relevant Event Logging (Principle 14).

**Why it matters for basis-core:** Several principles directly constrain basis-core behavior:

- **Principle 5** — basis-core must not know about specific OT protocols; the protocol adapter layer owns that translation
- **Principle 6** — evaluation must not require network I/O; fail-closed behavior must be explicit and tested, not assumed
- **Principle 7** — every failure mode that affects authorization decisions must be documented and deterministic
- **Principle 14** — audit records must be written once and never modified; `AuditEvent` implements append-only semantics in support of this principle

**Relevant for:** Decisions about evaluation behavior, failure mode contracts, and audit schema design.

---

## White paper rationale

**Document:** `whitepapers/identity-aware-authorization-for-operational-technology/` in basis-architecture

**Governs:** The full conceptual architecture: trust zones, enforcement point placement, identity propagation model, audit pipeline, and the operational context that motivates all of the above.

**Why it matters for basis-core:** The white paper establishes the deployment context in which basis-core will operate. The design constraints on the kernel — protocol-agnosticism, transport independence, deterministic evaluation, fail-closed defaults — are directly motivated by the OT deployment realities the white paper describes. When a design constraint seems unnecessarily restrictive from a software engineering perspective, the white paper provides the operational rationale.

---

## Relationship between this document and basis-architecture

This document is a contributor navigation aid. It does not reproduce or supersede the content of the basis-architecture documents it references. When in doubt about the authoritative position on any constraint, consult the basis-architecture document directly.

If a basis-architecture document is outdated, incomplete, or in conflict with operational reality, the appropriate response is to raise that in basis-architecture rather than to treat this repository as the implicit tie-breaker.
