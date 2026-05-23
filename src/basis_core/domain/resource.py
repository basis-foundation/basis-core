"""
basis_core.domain.resource — normalized descriptor for any OT resource.

A Resource is an immutable descriptor for any system object that can be the
target of an authorization decision: a controller point, a data stream, a
device configuration interface, a logical zone, or a protocol gateway.

Resources use a normalized identifier format that is protocol-agnostic. A
setpoint on a BACnet controller and a setpoint on a Modbus device are
different resources with different identifiers, but the identifier format is
consistent so that a single policy can reference both without protocol-specific
logic.

Identifier format
─────────────────
  "{type}:{qualifier[:{subqualifier}...]}"

  The type prefix must be a lowercase alphanumeric/hyphen/underscore string.
  Each qualifier segment must be non-empty.

  Examples:
    "hvac:zone-a"           HVAC controller in zone A
    "sensor:co2:lobby"      CO₂ sensor in the lobby subzone
    "device:chiller-1"      Generic OT device (protocol-agnostic)
    "zone:floor-2"          Logical zone grouping
    "gateway:bacnet-gw-01"  BACnet/IP gateway

Validation rules
────────────────
- ``id`` must match the resource identifier format and be non-empty.
- ``name`` must be non-empty.

ResourceType
────────────
Types reflect OT domain concepts, not protocol identities. DEVICE covers any
field device regardless of the protocol adapter that serves it. Adding support
for a new protocol means adding a new adapter, not a new ResourceType.
"""

from __future__ import annotations

import re
from enum import Enum

from pydantic import BaseModel, field_validator

# Compiled pattern for normalized resource identifier validation.
# Segments are separated by colons. Each segment: lowercase, digits, hyphens, underscores.
_RESOURCE_ID_RE = re.compile(r"^[a-z][a-z0-9_-]*(:[a-z0-9][a-z0-9_:/-]*)$")


class ResourceType(str, Enum):
    """OT resource classifications used in policy and audit records."""

    HVAC = "hvac"  # HVAC controller (setpoint, mode, fan speed, …)
    SENSOR = "sensor"  # Environmental sensor (CO₂, temperature, occupancy, …)
    ZONE = "zone"  # Logical grouping of physical resources
    DEVICE = "device"  # Generic OT device not covered by a more specific type
    GATEWAY = "gateway"  # Protocol bridge or edge gateway


class Resource(BaseModel):
    """
    Immutable descriptor for an OT resource that can be authorized against.

    Fields
    ──────
    id          Canonical normalized identifier. Appears in audit records and
                policy rules. Stable — treat as an external identifier.
                Must match the "{type}:{qualifier}" format.
    type        ResourceType classification.
    name        Short name component (qualifier after the type prefix).
                Must be non-empty.
    zone        Logical zone this resource belongs to. None for zone resources.
    description Human-readable label. Informational only.
    attrs       Arbitrary additional attributes for ABAC policy conditions.
                Examples: ``{"floor": "2", "criticality": "high"}``
    """

    id: str
    type: ResourceType
    name: str
    zone: str | None = None
    description: str | None = None
    attrs: dict[str, str] = {}

    model_config = {"frozen": True}

    @field_validator("id", mode="after")
    @classmethod
    def validate_resource_id_format(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("resource id must not be empty or whitespace-only")
        if not _RESOURCE_ID_RE.match(v):
            raise ValueError(
                f"resource id {v!r} does not match the required format "
                "'{type}:{qualifier}' (e.g. 'hvac:zone-a', 'sensor:co2:lobby'). "
                "Use only lowercase letters, digits, hyphens, underscores, "
                "and colons as separators."
            )
        return v

    @field_validator("name", mode="after")
    @classmethod
    def name_must_not_be_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("resource name must not be empty or whitespace-only")
        return v

    def __str__(self) -> str:
        return self.id


def build_resource_id(resource_type: ResourceType, *parts: str) -> str:
    """
    Construct a normalized resource identifier.

    build_resource_id(ResourceType.HVAC, "zone-a")             → "hvac:zone-a"
    build_resource_id(ResourceType.SENSOR, "co2", "lobby")     → "sensor:co2:lobby"
    build_resource_id(ResourceType.DEVICE, "chiller-1")        → "device:chiller-1"

    Raises ValueError if no qualifier parts are provided.
    """
    if not parts:
        raise ValueError("build_resource_id requires at least one qualifier part after the type.")
    return ":".join([resource_type.value] + list(parts))


def parse_resource_id(resource_id: str) -> tuple[str, list[str]]:
    """
    Parse a normalized resource identifier into its type prefix and qualifiers.

    Returns (type_str, qualifiers).

    parse_resource_id("hvac:zone-a")        → ("hvac",   ["zone-a"])
    parse_resource_id("sensor:co2:lobby")   → ("sensor", ["co2", "lobby"])
    parse_resource_id("device:chiller-1")   → ("device", ["chiller-1"])

    Raises ValueError if the identifier contains no colon separator.
    """
    if ":" not in resource_id:
        raise ValueError(
            f"resource id {resource_id!r} is missing a colon separator. "
            "Expected format: '{type}:{qualifier}'."
        )
    parts = resource_id.split(":")
    return parts[0], parts[1:]
