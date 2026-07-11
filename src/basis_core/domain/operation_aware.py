"""
basis_core.domain.operation_aware — the six optional, independently-nested
context value objects published by `basis-schemas` v0.2.0's
`operation-aware-decision-request` contract.

This module is the third production module added under `src/basis_core/`
for `basis-core` v0.2.0 (see
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`, Milestone 2,
PR 7 — "Operation-aware context value objects"), after PR 5's
`operation_aware_vocabulary.py` and PR 6's `evidence.py`. It implements
exactly the six nested `*_shape` objects the published
`operation-aware-decision-request` contract (PR C) defines as optional,
top-level fields on the future request:

  OperationAwareLocation           `location_shape` — optional physical/
                                    logical location context (site, building,
                                    zone, area).
  OperationAwareDevice              `device_shape` — optional device context
                                    (device identifier, device class).
  OperationAwareProtocolContext     `protocol_context_shape` — optional,
                                    protocol-neutral provenance context
                                    (protocol label, protocol-native
                                    operation name).
  OperationAwareSafetyContext       `safety_context_shape` — optional
                                    supplied safety-relevant context (mode,
                                    classification, constraint identifiers).
  OperationAwareEnvironmentContext  `environment_context_shape` — optional
                                    supplied operational-environment context
                                    (mode, condition identifiers).
  OperationAwareRiskContext         `risk_context_shape` — optional supplied
                                    risk context (classification, score).

Architectural boundary — normalized facts, not conclusions
────────────────────────────────────────────────────────────
Every model in this module carries **supplied, already-normalized context**
only. None of them:
  - authenticate an identity
  - retrieve device information from a network or topology service
  - inspect live network or protocol state
  - parse a protocol payload (BACnet, Modbus, OPC UA, MQTT, DNP3, IEC 61850,
    KNX, Niagara, or any other protocol)
  - derive, calculate, or combine a risk score
  - calculate or infer safety severity or an emergency condition
  - infer operation intent from an action string
  - interpret policy or make an authorization decision
  - establish trust in the evidence or context they carry

A `OperationAwareRiskContext.score` of `0.62` is a supplied number, not a
calculated one; a `OperationAwareSafetyContext.mode` of
``"interlock-engaged"`` is a supplied label, not this module's own
determination that an interlock is, in fact, engaged. The kernel's future
policy layer may evaluate conditions against these values — this module
does not.

Independently optional, no cross-field consistency
────────────────────────────────────────────────────
Per the published contract, every field within every one of these six
objects is independently optional — none of these types requires a full
"hierarchy" (e.g. site → building → zone → area) or enforces parent/child
relationships, cross-field consistency, or any relationship between
sibling fields. None of these types performs topology lookup, a topology
graph, device lookup, protocol parsing, or risk/safety calculation.

No duplication of PR 5/PR 6 types
────────────────────────────────────
None of these six objects reuses `RedactionClassification`, `ReasonCode`,
`EvidenceDigest`, `IdentityEvidenceReference`, or `AdapterEvidenceReference`
— the published contract does not nest any of those types inside these six
shapes (evidence references are separate, sibling, optional fields on the
future request itself, not nested inside these context objects). This
module has no import dependency on `evidence.py` or
`operation_aware_vocabulary.py`.

Not implemented by this module (deferred to later, separately-scoped
roadmap PRs): `OperationAwareDecisionRequest` itself and its flat scalar
fields — including `resource`, `resource_type`, and `operation_intent`,
which are fields on the request, not on any object in this module (PR 8);
request-level serialization round-trip tests (PR 9); any policy, condition,
selector, trace, audit, or evaluator behavior (Milestone 4 onward).

Public API status: internal to the operation-aware package for now, exactly
like `operation_aware_vocabulary` (PR 5) and `evidence` (PR 6). Not
re-exported from `basis_core.domain` or any other package `__init__.py`;
see `docs/public-api.md`'s "Open API questions" convention and Section 6 of
the roadmap plan for when operation-aware symbols are expected to graduate
to the stable public API (Milestone 11, PR 35).
"""

from __future__ import annotations

import math
import re

from pydantic import BaseModel, field_validator

# Open, lowercase, deployment-defined label pattern — reproduced verbatim
# from the vendored `operation-aware-decision-request` contract's
# `open_identifier_pattern` (also used, byte-identically, for
# `device_class`, `protocol_context.protocol`, `safety_context.mode`,
# `safety_context.classification`, `environment_context.mode`, and
# `risk_context.classification`). Structural shape only: this pattern does
# not imply, enumerate, or validate against any specific closed vocabulary
# of modes, classes, or classifications.
_OPEN_IDENTIFIER_RE = re.compile(r"^[a-z][a-z0-9_-]*$")


def _require_non_empty_if_present(
    value: str | None, *, field_name: str, type_name: str
) -> str | None:
    """Shared non-empty/non-whitespace-only check for optional string
    fields that, per the published contract, must be non-empty *when
    present* (every identifier field in this module)."""
    if value is not None and not value.strip():
        raise ValueError(
            f"{type_name}.{field_name} must not be empty or whitespace-only when provided."
        )
    return value


def _require_open_identifier_if_present(
    value: str | None, *, field_name: str, type_name: str
) -> str | None:
    """Shared open-identifier-pattern check for optional string fields that,
    per the published contract, must match `open_identifier_pattern` when
    present (`device_class`, `protocol_context.protocol`,
    `safety_context.mode`/`classification`, `environment_context.mode`,
    `risk_context.classification`)."""
    if value is None:
        return value
    if not _OPEN_IDENTIFIER_RE.match(value):
        raise ValueError(
            f"{type_name}.{field_name} {value!r} does not match the required pattern "
            r"'^[a-z][a-z0-9_-]*$' (open, lowercase, deployment-defined label)."
        )
    return value


class OperationAwareLocation(BaseModel):
    """
    Optional physical/logical location context in which a resource sits —
    the `location_shape` nested object on `operation-aware-decision-request`.

    Every field is independently optional; this type does not require a
    full site/building/zone/area hierarchy, does not enforce parent/child
    relationships between levels, and implements no topology lookup or
    topology graph.

    Optional fields
    ───────────────
    site_id      Identifier of the site, when known. Non-empty when present.
    building_id  Identifier of the building, when known. Non-empty when
                 present.
    zone_id      Identifier of the zone, when known. Non-empty when present.
    area_id      Identifier of the area, when known. Non-empty when present.
    """

    site_id: str | None = None
    building_id: str | None = None
    zone_id: str | None = None
    area_id: str | None = None

    model_config = {"frozen": True, "extra": "forbid"}

    @field_validator("site_id", mode="after")
    @classmethod
    def site_id_must_not_be_empty_if_present(cls, v: str | None) -> str | None:
        return _require_non_empty_if_present(
            v, field_name="site_id", type_name="OperationAwareLocation"
        )

    @field_validator("building_id", mode="after")
    @classmethod
    def building_id_must_not_be_empty_if_present(cls, v: str | None) -> str | None:
        return _require_non_empty_if_present(
            v, field_name="building_id", type_name="OperationAwareLocation"
        )

    @field_validator("zone_id", mode="after")
    @classmethod
    def zone_id_must_not_be_empty_if_present(cls, v: str | None) -> str | None:
        return _require_non_empty_if_present(
            v, field_name="zone_id", type_name="OperationAwareLocation"
        )

    @field_validator("area_id", mode="after")
    @classmethod
    def area_id_must_not_be_empty_if_present(cls, v: str | None) -> str | None:
        return _require_non_empty_if_present(
            v, field_name="area_id", type_name="OperationAwareLocation"
        )


class OperationAwareDevice(BaseModel):
    """
    Optional device context — the `device_shape` nested object on
    `operation-aware-decision-request`.

    Distinct from a request's `resource` field: `resource` is the
    authorization target, `device` is the physical or logical device
    involved in exposing or acting on that resource — they are not assumed
    to always be identical. Protocol-neutral: carries no device credential,
    no raw device configuration, and this type implements no live device
    lookup.

    Optional fields
    ───────────────
    device_id     Identifier of the specific device involved, when known.
                  Non-empty when present.
    device_class  Operational category of device (e.g. ``"controller"``,
                  ``"sensor"``, ``"actuator"``, ``"gateway"``), independent
                  of the specific device identity. Open, lowercase label
                  (`^[a-z][a-z0-9_-]*$`) — not a closed enum.
    """

    device_id: str | None = None
    device_class: str | None = None

    model_config = {"frozen": True, "extra": "forbid"}

    @field_validator("device_id", mode="after")
    @classmethod
    def device_id_must_not_be_empty_if_present(cls, v: str | None) -> str | None:
        return _require_non_empty_if_present(
            v, field_name="device_id", type_name="OperationAwareDevice"
        )

    @field_validator("device_class", mode="after")
    @classmethod
    def device_class_must_be_open_identifier_if_present(cls, v: str | None) -> str | None:
        return _require_open_identifier_if_present(
            v, field_name="device_class", type_name="OperationAwareDevice"
        )


class OperationAwareProtocolContext(BaseModel):
    """
    Optional protocol evidence/provenance context — the
    `protocol_context_shape` nested object on
    `operation-aware-decision-request`.

    Evidence only: this type's presence on a future request does not make
    the kernel protocol-aware. It carries no protocol-specific payload
    field and has no protocol library dependency; the kernel may later
    match policy against the normalized string context here, but this type
    implements no parsing of BACnet, Modbus, OPC UA, MQTT, DNP3, IEC 61850,
    KNX, Niagara, REST, or any other protocol.

    Optional fields
    ───────────────
    protocol   Open, lowercase protocol label carried as safe provenance
               metadata only (e.g. ``"bacnet"``, ``"modbus"``), using the
               same pattern (`^[a-z][a-z0-9_-]*$`) as
               `AdapterEvidenceReference.protocol`. Not a closed enum, and
               never a protocol-specific payload field.
    operation  The protocol-native operation name the adapter normalized
               (for example a BACnet service name or a Modbus function),
               preserved as evidence alongside the request's own normalized
               `action`. Free-form, non-empty string when present:
               protocol-native operation names do not share one charset,
               so no cross-protocol pattern is enforced. Evidence only —
               this is a label, never a protocol payload; this type
               implements no protocol parsing.
    """

    protocol: str | None = None
    operation: str | None = None

    model_config = {"frozen": True, "extra": "forbid"}

    @field_validator("protocol", mode="after")
    @classmethod
    def protocol_must_be_open_identifier_if_present(cls, v: str | None) -> str | None:
        return _require_open_identifier_if_present(
            v, field_name="protocol", type_name="OperationAwareProtocolContext"
        )

    @field_validator("operation", mode="after")
    @classmethod
    def operation_must_not_be_empty_if_present(cls, v: str | None) -> str | None:
        return _require_non_empty_if_present(
            v, field_name="operation", type_name="OperationAwareProtocolContext"
        )


class OperationAwareSafetyContext(BaseModel):
    """
    Optional, supplied safety-relevant context — the `safety_context_shape`
    nested object on `operation-aware-decision-request`.

    Deterministic, structured data only. This type does not design a safety
    system, does not claim safety certification, does not make basis-core a
    safety controller, carries no control command or executable policy, and
    does not determine whether a state is, in fact, safe.

    Optional fields
    ───────────────
    mode            Deployment-defined, open lowercase label for the safety
                     mode in effect (for example a lockout/tagout or
                     interlock-engaged mode), when applicable. Open label
                     (`^[a-z][a-z0-9_-]*$`) — not a closed enum:
                     basis-architecture has not published a closed
                     safety-mode vocabulary.
    classification   Deployment-defined, open lowercase safety
                     classification label, when applicable. Same pattern as
                     `mode`.
    constraint_ids   Identifiers of safety constraints applicable to this
                     request, when known. Stored as an immutable tuple;
                     item type (string) is validated, but this type does
                     not itself enforce item non-emptiness or define what a
                     constraint identifier resolves to.
    """

    mode: str | None = None
    classification: str | None = None
    constraint_ids: tuple[str, ...] = ()

    model_config = {"frozen": True, "extra": "forbid"}

    @field_validator("mode", mode="after")
    @classmethod
    def mode_must_be_open_identifier_if_present(cls, v: str | None) -> str | None:
        return _require_open_identifier_if_present(
            v, field_name="mode", type_name="OperationAwareSafetyContext"
        )

    @field_validator("classification", mode="after")
    @classmethod
    def classification_must_be_open_identifier_if_present(cls, v: str | None) -> str | None:
        return _require_open_identifier_if_present(
            v, field_name="classification", type_name="OperationAwareSafetyContext"
        )


class OperationAwareEnvironmentContext(BaseModel):
    """
    Optional, supplied operational-environment context, distinct from
    safety context — the `environment_context_shape` nested object on
    `operation-aware-decision-request` (for example a maintenance mode or a
    degraded-connectivity condition).

    Illustrative only: this type does not define a closed environment-state
    ontology and implements no runtime discovery behavior.

    Optional fields
    ───────────────
    mode           Deployment-defined, open lowercase label for the
                   operational environment mode in effect (for example
                   ``"maintenance_mode"`` or ``"degraded_connectivity"`` —
                   illustrative, not a closed list), when applicable. Open
                   label (`^[a-z][a-z0-9_-]*$`).
    condition_ids  Identifiers of environment conditions applicable to this
                   request, when known. Stored as an immutable tuple; item
                   type (string) is validated, but this type does not
                   itself enforce item non-emptiness.
    """

    mode: str | None = None
    condition_ids: tuple[str, ...] = ()

    model_config = {"frozen": True, "extra": "forbid"}

    @field_validator("mode", mode="after")
    @classmethod
    def mode_must_be_open_identifier_if_present(cls, v: str | None) -> str | None:
        return _require_open_identifier_if_present(
            v, field_name="mode", type_name="OperationAwareEnvironmentContext"
        )


class OperationAwareRiskContext(BaseModel):
    """
    Optional, deployment-defined risk context — the `risk_context_shape`
    nested object on `operation-aware-decision-request`.

    This type defines no risk taxonomy, no risk engine, and no
    risk-calculation behavior, and makes no accuracy claim about any
    classification or score it carries — a supplied value is not a
    calculated or verified one.

    Optional fields
    ───────────────
    classification  Deployment-defined, open lowercase risk classification
                     label, when a deployment chooses to define one. Open
                     label (`^[a-z][a-z0-9_-]*$`). This type defines no
                     final risk taxonomy.
    score            Deployment-defined numeric risk score, when a
                     deployment chooses to define one. No bounds, scale, or
                     calculation method is defined or enforced — a consumer
                     must not assume any particular range without
                     deployment-specific documentation. Must be a finite
                     number when present; booleans are rejected (a `bool`
                     is not a risk score, even though `bool` is a Python
                     `int` subtype).
    """

    classification: str | None = None
    score: float | None = None

    model_config = {"frozen": True, "extra": "forbid"}

    @field_validator("classification", mode="after")
    @classmethod
    def classification_must_be_open_identifier_if_present(cls, v: str | None) -> str | None:
        return _require_open_identifier_if_present(
            v, field_name="classification", type_name="OperationAwareRiskContext"
        )

    @field_validator("score", mode="before")
    @classmethod
    def score_must_not_be_bool(cls, v: object) -> object:
        # Raised as ValueError, not TypeError: Pydantic's `field_validator`
        # only converts `ValueError`/`AssertionError` into its own
        # `ValidationError` — a `TypeError` raised here would propagate
        # unwrapped and break the uniform `ValidationError` contract every
        # other rejection in this module (and in `evidence.py`) relies on.
        if isinstance(v, bool):
            raise ValueError("OperationAwareRiskContext.score must be a number, not a boolean.")
        return v

    @field_validator("score", mode="after")
    @classmethod
    def score_must_be_finite_if_present(cls, v: float | None) -> float | None:
        if v is not None and not math.isfinite(v):
            raise ValueError(
                "OperationAwareRiskContext.score must be a finite number (not NaN or Infinity)."
            )
        return v
