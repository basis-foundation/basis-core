# ADR-0005 — Move JWT/OIDC Normalization Outside the Authorization Kernel

**Status**: Draft
**Date**: 2026-05-31

## Context

`basis-core` currently exports `subject_from_jwt()` from `basis_core.domain.subject`. This function accepts a decoded JWT payload dictionary and returns a `Subject` domain object. In its current form it assumes Keycloak/OIDC claim conventions: it reads roles from `payload["realm_access"]["roles"]`, extracts the subject identifier from `payload["sub"]`, and constructs a `Subject` from those claims.

This creates a kernel boundary concern.

The kernel boundary rules (`docs/architecture/kernel-boundary-rules.md` in `basis-architecture`) state that `basis-core` must not integrate directly with an identity provider and must not fetch JWKS endpoints, issue tokens, or call identity-provider-specific services. The `subject_from_jwt()` function does not fetch JWKS or call Keycloak directly, but it encodes Keycloak claim conventions into the kernel's domain layer. This is a softer violation of the same principle: the kernel's domain types should be identity-provider agnostic, and the normalization step that translates provider-specific claims into domain types should live outside the kernel.

The concern is practical, not just categorical. If the distribution's reference identity provider changes, or if a deployer uses Entra ID, Okta, or a custom OIDC provider with different claim structures, `subject_from_jwt()` will produce incorrect `Subject` objects without any visible error. A function that embeds IdP-specific assumptions inside the kernel creates a hidden dependency that violates the portability the kernel is designed to provide.

`basis-gateway` — the component being designed in `basis-architecture` — is the appropriate owner of JWT/OIDC normalization. The gateway authenticates callers, parses tokens, and must translate verified identity claims into kernel-compatible subject context. Placing that translation inside the kernel inverts the dependency: the kernel ends up knowing about runtime authentication details that the kernel should never see.

The `basis-core` public API documentation (`docs/public-api.md`) already tracks this as `OPEN: subject-from-jwt-placement`. This ADR formally resolves that open question.

## Decision

JWT and OIDC claim normalization belongs at the runtime boundary — `basis-gateway` or an equivalent trusted runtime component — not inside the authorization kernel.

The specific direction:

1. `subject_from_jwt()` should be deprecated in `basis-core` and removed in a future release. The deprecation should emit a `DeprecationWarning` so that any caller depending on the current import path receives visible notice.

2. The canonical location for JWT-to-Subject normalization is `basis-gateway`. The gateway is responsible for mapping identity-provider-specific claims into the `Subject` and `IdentityContext` types that the kernel accepts. That mapping is a gateway implementation concern and may vary by identity provider.

3. If a generic claim-mapping helper is warranted — one that does not assume any specific IdP claim structure — it belongs in a gateway-layer library or a future `basis-schemas` component, not in `basis-core`. Any helper retained in `basis-core` must accept arbitrary claim keys as parameters rather than encoding Keycloak-specific paths.

4. `basis-core` retains the `Subject`, `SubjectType`, and `IdentityContext` domain types and the `subject_from_jwt()` signature as a deprecated stub through the deprecation period. The domain types are stable; only the normalization function is moving.

5. The `subject_from_jwt()` function is part of the stable public API surface (`docs/public-api.md`). Its removal constitutes a breaking change under the compatibility rules in `docs/architecture/compatibility-philosophy.md` in `basis-architecture`. The deprecation period must be long enough that any caller depending on the current form has time to migrate.

## Rationale

**The kernel must remain IdP-agnostic.** A `basis-core` deployment that evaluates authorization requests should function correctly regardless of whether the surrounding deployment uses Keycloak, Entra ID, Okta, a custom OIDC provider, or certificate-based identity. Encoding Keycloak claim paths in the kernel's domain layer creates an undocumented constraint that narrows deployment flexibility without any kernel evaluation benefit.

**JWT normalization is a boundary concern, not an evaluation concern.** Policy evaluation uses the normalized `Subject` — its `id`, `roles`, `type`. It does not use the raw token format, the claim paths, the issuer, or the JWKS key material. Those are authentication-layer concerns. Keeping them in the kernel layer co-mingles authentication with authorization in a way that the kernel boundary explicitly prohibits.

**gateway-owned normalization is already the correct pattern.** The PoC's `auth.py` placed JWT verification and `subject_from_jwt()` in the API service (equivalent to `basis-gateway`), not in the policy engine layer. The current placement of `subject_from_jwt()` in `basis-core` was a convenience that predates the explicit gateway/kernel separation. The distribution design makes the correct boundary clear; the implementation should follow it.

## Consequences

**For basis-core:**

- `subject_from_jwt()` is marked deprecated. A `DeprecationWarning` is added to its implementation. It remains functional through the deprecation period.
- `docs/public-api.md` is updated to reflect the deprecated status and expected removal timeline.
- Existing tests that exercise `subject_from_jwt()` should be retained during the deprecation period and updated to use the replacement pattern when the function is removed.
- The `Subject`, `SubjectType`, and `IdentityContext` types are unaffected. They remain stable public API.

**For basis-gateway:**

- The gateway implementation owns JWT verification and claim-to-Subject normalization. It should not import `subject_from_jwt()` from `basis-core` beyond the deprecation period.
- The gateway's normalization step must be configurable or adaptable to different OIDC providers without requiring `basis-core` changes.

**For future basis-schemas:**

- A normalized subject/principal schema — defining what a verified, normalized identity context looks like when it crosses the trust boundary — is a candidate for `basis-schemas` once that component is established. This would give all distribution components a shared definition to work against, without encoding IdP specifics in any of them.

## Open Questions

**Should `subject_from_jwt()` be removed, deprecated with a replacement, or generalized?**

Three options: (a) remove it entirely, requiring gateway implementations to write their own normalization; (b) deprecate and provide a generic replacement that accepts configurable claim key paths rather than hardcoded Keycloak paths; (c) move it to a `basis-gateway` library package where it remains available but is no longer a kernel concern. Option (b) is the least disruptive but requires design work to define the generic interface. This decision should be made before `basis-gateway` v0.1 begins implementation.

**Should normalized subject/principal contracts move to basis-schemas?**

If `basis-schemas` is established as the shared contract layer for the distribution, the `Subject` type and `IdentityContext` schema may be more appropriate there than in `basis-core`. This is a larger question about the scope of `basis-schemas` and is not required for this ADR's resolution.

**Should this be resolved before basis-gateway implementation begins?**

Yes. The gateway's authentication module will need a clear, stable approach to JWT normalization. Building against a deprecated function that is expected to move creates a migration obligation at the worst possible time. Resolving the placement question early reduces implementation churn.

**What is the deprecation timeline?**

The appropriate timeline depends on the `basis-gateway` implementation schedule. Aligning the removal of `subject_from_jwt()` from `basis-core` with the `basis-gateway` v0.1 release — so that the gateway release includes its own normalization path — is the natural candidate. This should be confirmed during gateway implementation planning.

## Related Documents

- `docs/public-api.md` in this repository — `subject_from_jwt()` is listed as a stable public API symbol; this ADR initiates the deprecation process for it
- `docs/kernel-boundary.md` in this repository — the conceptual basis for why authentication concerns belong outside the kernel
- `docs/architecture/kernel-boundary-rules.md` in `basis-architecture` — the rule that the kernel must not integrate directly with identity providers
- `docs/architecture/basis-gateway.md` in `basis-architecture` — the gateway architecture that takes ownership of JWT normalization
- `docs/architecture/reference-vs-implementation.md` in `basis-architecture` — the distinction between reference implementation choices (PoC) and architecture decisions
