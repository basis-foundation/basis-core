"""
basis_core.domain.evidence — bounded references to identity and adapter
evidence produced outside the authorization kernel.

This module is the second production module added under `src/basis_core/`
for `basis-core` v0.2.0 (see
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`, Milestone 2,
PR 6 — "Evidence-reference models"). It implements the two evidence-reference
value objects published by `basis-schemas` v0.2.0's `identity-evidence-reference`
and `adapter-evidence-reference` contracts (ADR-0003 §7-8):

  IdentityEvidenceReference  A safe reference to trusted identity evidence
                             produced by basis-identity (or an equivalent
                             identity source): a stable reference identifier,
                             a structural evidence digest, an
                             identity-provider-neutral source label, optional
                             normalization/mapping version provenance, a
                             redaction classification, and optional
                             association with a decision request and a
                             broader correlated operation.
  AdapterEvidenceReference   A safe reference to normalized adapter evidence
                             produced by basis-adapters: the same reference
                             shape, but with an adapter source label and an
                             optional, open, protocol-neutral provenance
                             label instead of an identity source.

Core architectural boundary — reference, not proof
────────────────────────────────────────────────────
These models represent **a reference to evidence**. They do not represent
**proof that evidence is authentic**. Neither type:
  - retrieves the evidence it references
  - verifies the evidence source or producer
  - validates a cryptographic signature
  - validates evidence provenance beyond carrying opaque, caller-supplied
    provenance labels
  - verifies digest authenticity — `EvidenceDigest` carries a structurally
    well-formed algorithm label and hex value; it makes no claim that the
    digest was correctly computed or matches any actual evidence content
  - canonicalizes, retains, or displays raw evidence
  - authenticates the evidence producer

A structurally valid digest is not authenticity proof. `basis-core` carries
these references and their metadata only; establishing trust in the
evidence they point to is explicitly out of scope for this contract and this
module, exactly as `basis-schemas`' own published contracts state.

No raw evidence
────────────────
Neither model has a field capable of holding a raw access token, ID token,
refresh token, JWT, bearer token, authorization header, cookie, session
secret, client secret, password, private key, raw claim set, or raw protocol
payload — the shape simply does not admit such a value. Both models also
reject unknown fields at construction time (`extra="forbid"`), matching the
published contracts' `additional_properties: false` constraint, so no
caller can smuggle a raw-evidence-shaped field in under an unanticipated
name either.

Not implemented by this module (deferred to later, separately-scoped
roadmap PRs): operation-aware context value objects (PR 7), the
operation-aware request/response models (PR 8-10), any policy or condition
model (Milestone 4+), and any trust, verification, or signature-checking
behavior for the evidence these references point to (out of scope for any
roadmap PR — ownership stays with basis-identity / basis-adapters and the
components that consume these references).

Public API status: internal to the operation-aware package for now, exactly
like `operation_aware_vocabulary` (PR 5). Not re-exported from
`basis_core.domain` or any other package `__init__.py`; see
`docs/public-api.md`'s "Open API questions" convention and Section 6 of the
roadmap plan for when operation-aware symbols are expected to graduate to
the stable public API (Milestone 11, PR 35).
"""

from __future__ import annotations

import re

from pydantic import BaseModel, field_validator

from basis_core.domain.operation_aware_vocabulary import RedactionClassification

# Structural patterns, copied verbatim from the vendored
# `identity-evidence-reference` / `adapter-evidence-reference` contracts'
# shared `evidence_digest_shape` (the two contracts define byte-identical
# digest shapes). No hashing, canonicalization, or verification behavior is
# implemented or implied by these patterns — structural shape only.
_DIGEST_ALGORITHM_RE = re.compile(r"^[a-z][a-z0-9]*(-[a-z0-9]+)*$")
_DIGEST_VALUE_RE = re.compile(r"^[a-f0-9]+$")

# Protocol label pattern, copied verbatim from the vendored
# `adapter-evidence-reference` contract's `protocol` field. Open, lowercase
# label — not a closed enum. Carried as opaque provenance metadata only; its
# presence does not make basis-core protocol-aware.
_PROTOCOL_RE = re.compile(r"^[a-z][a-z0-9_-]*$")


def _require_non_empty(value: str, *, field_name: str, type_name: str) -> str:
    """Shared non-empty/non-whitespace-only check for required string
    fields, reused by both evidence-reference models and `EvidenceDigest`."""
    if not value.strip():
        raise ValueError(f"{type_name}.{field_name} must not be empty or whitespace-only.")
    return value


def _require_non_empty_if_present(
    value: str | None, *, field_name: str, type_name: str
) -> str | None:
    """Shared non-empty check for optional string fields that, per the
    published contracts, must be non-empty *when present* (`request_id` on
    both evidence-reference contracts)."""
    if value is not None and not value.strip():
        raise ValueError(
            f"{type_name}.{field_name} must not be empty or whitespace-only when provided."
        )
    return value


class EvidenceDigest(BaseModel):
    """
    A structural digest reference for an evidence artifact — the
    `evidence_digest_shape` nested object shared, byte-identically, by the
    `identity-evidence-reference` and `adapter-evidence-reference`
    contracts.

    Fields
    ──────
    algorithm  Open, lowercase kebab-case digest algorithm label (e.g.
               ``"sha-256"``, ``"sha3-256"``). Not a closed enum — this
               contract validates only that the label is well-formed, not
               that it names a specific approved algorithm.
    value      The digest value as lowercase hexadecimal, with no ``"0x"``
               or ``"algorithm:"`` prefix, whitespace, or padding.

    Structural metadata only. This type does not implement, canonicalize, or
    verify hashing — evidence producers (basis-identity, basis-adapters) own
    deterministic digest generation, and this type makes no
    tamper-evidence or cryptographic-authenticity claim about the value it
    carries.

    Internal to this module — not part of `basis-schemas`' `required`/
    `optional` top-level field lists for either evidence-reference contract;
    it exists here only because both contracts nest it identically under
    `evidence_digest`.
    """

    algorithm: str
    value: str

    model_config = {"frozen": True, "extra": "forbid"}

    @field_validator("algorithm", mode="after")
    @classmethod
    def algorithm_must_be_well_formed(cls, v: str) -> str:
        v = _require_non_empty(v, field_name="algorithm", type_name="EvidenceDigest")
        if not _DIGEST_ALGORITHM_RE.match(v):
            raise ValueError(
                f"EvidenceDigest.algorithm {v!r} does not match the required pattern "
                r"'^[a-z][a-z0-9]*(-[a-z0-9]+)*$' (lowercase kebab-case, e.g. 'sha-256')."
            )
        return v

    @field_validator("value", mode="after")
    @classmethod
    def value_must_be_lowercase_hex(cls, v: str) -> str:
        v = _require_non_empty(v, field_name="value", type_name="EvidenceDigest")
        if not _DIGEST_VALUE_RE.match(v):
            raise ValueError(
                f"EvidenceDigest.value {v!r} does not match the required pattern "
                r"'^[a-f0-9]+$' (lowercase hexadecimal, no '0x' or 'algorithm:' prefix, "
                "no whitespace)."
            )
        return v


class IdentityEvidenceReference(BaseModel):
    """
    A safe reference to trusted identity evidence produced outside the
    authorization kernel (typically by basis-identity).

    This is a *reference*, not the evidence itself and not proof that the
    evidence is authentic — see this module's docstring. Carries no raw
    access token, ID token, refresh token, JWT, cookie, session secret,
    client secret, password, private key, or raw claim set; no such field
    exists on this type, and unknown fields are rejected at construction.

    Required fields
    ───────────────
    reference_id             Stable, deterministic identifier for the
                              referenced identity evidence artifact.
                              Non-empty.
    evidence_digest           Structural digest reference (`EvidenceDigest`).
    identity_source           Opaque, non-empty label identifying the
                              identity source or authority that produced the
                              underlying evidence (e.g. an issuer or provider
                              reference). Deliberately provider-neutral.
    redaction_classification  Handling requirement for the referenced
                              evidence — not a grant of permission to expose
                              it. See `RedactionClassification`.

    Optional fields
    ───────────────
    normalization_version  Version of the identity-normalization mapping
                            that produced the canonical identity context
                            this evidence backs, when tracked. `None` when
                            not applicable or not tracked.
    mapping_version         Version of the claim-mapping applied when
                            translating provider claims, when applicable.
                            `None` when not used or not tracked.
    request_id              The decision request's `request_id` this
                            evidence supports, when already known. Must be
                            non-empty when provided; `None` because identity
                            evidence is commonly produced before a specific
                            authorization request exists.
    correlation_id           Optional caller-provided trace identifier for
                            cross-system correlation, passed through
                            verbatim. No format constraint beyond being a
                            string or `None`.
    """

    reference_id: str
    evidence_digest: EvidenceDigest
    identity_source: str
    redaction_classification: RedactionClassification
    normalization_version: str | None = None
    mapping_version: str | None = None
    request_id: str | None = None
    correlation_id: str | None = None

    model_config = {"frozen": True, "extra": "forbid"}

    @field_validator("reference_id", mode="after")
    @classmethod
    def reference_id_must_not_be_empty(cls, v: str) -> str:
        return _require_non_empty(
            v, field_name="reference_id", type_name="IdentityEvidenceReference"
        )

    @field_validator("identity_source", mode="after")
    @classmethod
    def identity_source_must_not_be_empty(cls, v: str) -> str:
        return _require_non_empty(
            v, field_name="identity_source", type_name="IdentityEvidenceReference"
        )

    @field_validator("request_id", mode="after")
    @classmethod
    def request_id_must_not_be_empty_if_present(cls, v: str | None) -> str | None:
        return _require_non_empty_if_present(
            v, field_name="request_id", type_name="IdentityEvidenceReference"
        )


class AdapterEvidenceReference(BaseModel):
    """
    A safe reference to normalized adapter evidence produced outside the
    authorization kernel (typically by basis-adapters).

    This is a *reference*, not the evidence itself and not proof that the
    evidence is authentic — see this module's docstring. Carries no raw
    protocol payload, packet, frame, credential, password, API key, private
    key, or unredacted device secret; no such field exists on this type, and
    unknown fields are rejected at construction. This type remains protocol
    agnostic: `protocol` (when present) is an opaque provenance label, never
    a parsed or interpreted value, and this type does not understand
    BACnet, Modbus, OPC UA, MQTT, DNP3, IEC 61850, KNX, Niagara, or any
    other protocol.

    Required fields
    ───────────────
    reference_id             Stable, deterministic identifier for the
                              referenced adapter evidence artifact.
                              Non-empty.
    evidence_digest           Structural digest reference (`EvidenceDigest`).
    adapter_source             Opaque, non-empty label identifying the
                              adapter or normalization component that
                              produced the underlying evidence.
    redaction_classification  Handling requirement for the referenced
                              evidence — not a grant of permission to expose
                              it. See `RedactionClassification`.

    Optional fields
    ───────────────
    normalization_version  Version of the adapter normalization logic that
                            produced this evidence, when tracked. `None`
                            when not applicable or not tracked.
    mapping_version         Version of the protocol-to-canonical mapping
                            table applied, when applicable. `None` when no
                            such mapping was used or not tracked.
    protocol                 Open, lowercase protocol label carried as safe
                            provenance metadata only (e.g. ``"modbus"``,
                            ``"bacnet"``). Not a closed enum. A label only —
                            never a protocol-specific operation payload
                            field.
    request_id              The decision request's `request_id` this
                            evidence supports, when already known. Must be
                            non-empty when provided; `None` because adapter
                            evidence is commonly produced during
                            normalization, ahead of the specific
                            authorization request the gateway later
                            assembles.
    correlation_id           Optional caller-provided trace identifier for
                            cross-system correlation, passed through
                            verbatim. No format constraint beyond being a
                            string or `None`.
    """

    reference_id: str
    evidence_digest: EvidenceDigest
    adapter_source: str
    redaction_classification: RedactionClassification
    normalization_version: str | None = None
    mapping_version: str | None = None
    protocol: str | None = None
    request_id: str | None = None
    correlation_id: str | None = None

    model_config = {"frozen": True, "extra": "forbid"}

    @field_validator("reference_id", mode="after")
    @classmethod
    def reference_id_must_not_be_empty(cls, v: str) -> str:
        return _require_non_empty(
            v, field_name="reference_id", type_name="AdapterEvidenceReference"
        )

    @field_validator("adapter_source", mode="after")
    @classmethod
    def adapter_source_must_not_be_empty(cls, v: str) -> str:
        return _require_non_empty(
            v, field_name="adapter_source", type_name="AdapterEvidenceReference"
        )

    @field_validator("protocol", mode="after")
    @classmethod
    def protocol_must_be_well_formed_if_present(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if not _PROTOCOL_RE.match(v):
            raise ValueError(
                f"AdapterEvidenceReference.protocol {v!r} does not match the required "
                r"pattern '^[a-z][a-z0-9_-]*$' (open, lowercase provenance label)."
            )
        return v

    @field_validator("request_id", mode="after")
    @classmethod
    def request_id_must_not_be_empty_if_present(cls, v: str | None) -> str | None:
        return _require_non_empty_if_present(
            v, field_name="request_id", type_name="AdapterEvidenceReference"
        )
