"""
basis_core.adapters — adapter protocol and normalization utilities.

Adapters are the boundary between external protocol representations and the
basis_core domain model. Each adapter is responsible for:

  1. Receiving a message in its native protocol format.
  2. Normalizing it into a DecisionRequest (for commands) or domain events
     (for telemetry and state updates).
  3. Attaching verified identity context to the normalized representation.
  4. Returning the result of the authorization decision to the protocol layer.

Adapters must not contain authorization logic. They normalize; core evaluates.
Protocol-specific field names, register maps, object identifiers, topic schemas,
and wire formats must not appear outside the adapter that owns them.

Contents
────────
  base.py    AdapterBase (Protocol) and NormalizedEvent.
             AdapterBase — lifecycle interface all adapters implement.
             NormalizedEvent — protocol-agnostic output of adapter normalization.

Concrete adapter implementations (BACnet, Modbus, MQTT, etc.) live outside
this package or in a separate repository. They depend on basis_core but are
not part of it.

Public API
──────────
All stable public symbols are available directly from this package.
See ``docs/public-api.md`` for the full inventory and stability tiers.
"""

from basis_core.adapters.base import AdapterBase, NormalizedEvent

__all__ = [
    "AdapterBase",
    "NormalizedEvent",
]
