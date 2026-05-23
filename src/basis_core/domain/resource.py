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

  Examples:
    "hvac:zone-a"           HVAC controller in zone A
    "sensor:co2:lobby"      CO₂ sensor in the lobby subzone
    "device:chiller-1"      Generic OT device (protocol-agnostic)
    "zone:floor-2"          Logical zone grouping
    "gateway:bacnet-gw-01"  BACnet/IP gateway

ResourceType
────────────
Types reflect OT domain concepts, not protocol identities. DEVICE covers any
field device regardless of the protocol adapter that serves it. Adding support
for a new protocol means adding a new adapter, not a new ResourceType.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel


class ResourceType(str, Enum):
    """OT resource classifications used in policy and audit records."""

    HVAC    = "hvac"     # HVAC controller (setpoint, mode, fan speed, …)
    SENSOR  = "sensor"   # Environmental sensor (CO₂, temperature, occupancy, …)
    ZONE    = "zone"     # Logical grouping of physical resources
    DEVICE  = "device"   # Generic OT device not covered by a more specific type
    GATEWAY = "gateway"  # Protocol bridge or edge gateway


class Resource(BaseModel):
    """
    Immutable descriptor for an OT resource that can be authorized against.

    Fields
    ──────
    id          Canonical normalized identifier. Appears in audit records and
                policy rules. Stable — treat as an external identifier.
    type        ResourceType classification.
    name        Short name component (qualifier after the type prefix).
    zone        Logical zone this resource belongs to. None for zone resources.
    description Human-readable label. Informational only.
    attrs       Arbitrary additional attributes for ABAC policy conditions.
                Examples: ``{"floor": "2", "criticality": "high"}``
    """

    id:          str
    type:        ResourceType
    name:        str
    zone:        Optional[str]       = None
    description: Optional[str]       = None
    attrs:       dict[str, str]      = {}

    model_config = {"frozen": True}

    def __str__(self) -> str:
        return self.id


def build_resource_id(resource_type: ResourceType, *parts: str) -> str:
    """
    Construct a normalized resource identifier.

    build_resource_id(ResourceType.HVAC, "zone-a")             → "hvac:zone-a"
    build_resource_id(ResourceType.SENSOR, "co2", "lobby")     → "sensor:co2:lobby"
    build_resource_id(ResourceType.DEVICE, "chiller-1")        → "device:chiller-1"
    """
    return ":".join([resource_type.value] + list(parts))


def parse_resource_id(resource_id: str) -> tuple[str, list[str]]:
    """
    Parse a normalized resource identifier into its type prefix and qualifiers.

    Returns (type_str, qualifiers).

    parse_resource_id("hvac:zone-a")        → ("hvac",   ["zone-a"])
    parse_resource_id("sensor:co2:lobby")   → ("sensor", ["co2", "lobby"])
    parse_resource_id("device:chiller-1")   → ("device", ["chiller-1"])
    """
    parts = resource_id.split(":")
    return parts[0], parts[1:]
