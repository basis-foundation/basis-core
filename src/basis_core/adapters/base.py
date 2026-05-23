"""
basis_core.adapters.base — AdapterBase protocol and NormalizedEvent.

AdapterBase is the lifecycle interface that all protocol adapters implement.
The application startup iterates a list of registered adapters and calls
start() on each. Shutdown calls stop() in reverse order. The application
does not contain per-adapter logic; it calls the interface.

NormalizedEvent is the output type adapters produce when they receive a
field-protocol message. It carries enough context for the enforcement point
to construct a DecisionRequest without any knowledge of the originating
protocol.

Design constraints
──────────────────
- Adapter implementations must not import from basis_core.enforcement.
- Adapters must not perform authorization evaluation. They normalize.
- The adapter_id is a stable identifier that appears in audit records.
  It must not change after an adapter is deployed to production.
- Protocol-specific logic must not appear outside the adapter that owns it.
  A BACnet object identifier must not appear in a DecisionRequest field name.
  A Modbus register address must not appear in a policy rule.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import BaseModel


class NormalizedEvent(BaseModel):
    """
    A protocol-agnostic representation of a field-protocol message.

    This is the output of adapter normalization and the input to the
    enforcement point. It carries the three authorization primitives
    (subject_id, resource_id, action) plus the context and payload the
    enforcement point may need.

    Fields
    ──────
    adapter_id    Identifier of the adapter that produced this event.
    protocol      Protocol name (e.g., "bacnet", "modbus-tcp", "mqtt").
    subject_id    Identity of the requesting subject, if available.
                  May be None for device-originated telemetry.
    resource_id   Normalized resource identifier.
    action        Action name from the basis_core.domain.action vocabulary.
    context       Key/value context for policy conditions.
    payload       Original message payload, normalized to a plain dict.
                  The policy engine does not inspect this field. It is
                  forwarded to downstream handlers and audit detail.
    """

    adapter_id: str
    protocol: str
    subject_id: str | None = None
    resource_id: str | None = None
    action: str
    context: dict[str, str] = {}
    payload: dict[str, object] = {}


@runtime_checkable
class AdapterBase(Protocol):
    """
    Lifecycle interface for OT protocol adapters.

    All adapters expose two lifecycle methods and two identifying attributes.
    The application calls start() to activate an adapter and stop() to shut
    it down. No adapter-specific logic belongs in the application startup.

    adapter_id  Stable identifier. Appears in audit records and adapter
                registry entries. Treat as an external identifier once deployed.
    protocol    Human-readable protocol name for observability and diagnostics.
    """

    adapter_id: str
    protocol: str

    def start(self) -> None:
        """Activate the adapter. Called once during application startup."""
        ...

    def stop(self) -> None:
        """Deactivate the adapter. Called during graceful shutdown."""
        ...
