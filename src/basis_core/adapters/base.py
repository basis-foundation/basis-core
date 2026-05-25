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

    ``NormalizedEvent`` is the output of adapter normalization and the input
    to the enforcement point. It carries the three authorization primitives
    (``subject_id``, ``resource_id``, ``action``) plus context and payload
    that downstream handlers may need.

    Normalization contract
    ──────────────────────
    Adapters that produce ``NormalizedEvent`` must follow these rules:

    - ``action`` must come from the ``basis_core.domain.action`` vocabulary.
      It must use the ``{verb}:{domain}[:{object}]`` format (e.g.
      ``"write:hvac:setpoint"``). Protocol-specific identifiers (BACnet object
      types, Modbus register addresses, MQTT topic fragments) must not appear
      in ``action``.

    - ``resource_id``, when present, must be a normalized identifier in the
      ``{type}:{qualifier}`` format (e.g. ``"hvac:zone-a"``). It must not
      contain protocol-specific names or addresses.

    - Protocol-specific data (BACnet object identifiers, Modbus register
      numbers, raw MQTT payloads) belongs in ``payload`` — not in ``action``,
      ``resource_id``, or ``context``. The policy engine does not inspect
      ``payload``; it is forwarded to audit detail and downstream handlers.

    - ``adapter_id`` must be stable. It appears in audit records and adapter
      registry entries. Once an adapter is deployed to production, its
      ``adapter_id`` must not change.

    - ``subject_id`` may be ``None`` for device-originated telemetry where no
      authenticated subject identity is available.

    Normalization changes are compatibility-sensitive
    ─────────────────────────────────────────────────
    Changing how a protocol message maps to ``action`` or ``resource_id`` is a
    breaking change for any policy that references those values. Introduce new
    normalized representations additively — do not rename or narrow existing
    mappings in deployed configurations.

    Fields
    ──────
    adapter_id    Stable identifier of the adapter that produced this event.
    protocol      Protocol name for observability (e.g., "bacnet", "modbus-tcp",
                  "mqtt"). Human-readable; does not appear in policy rules.
    subject_id    Identity of the requesting subject, or None for
                  device-originated telemetry without an authenticated subject.
    resource_id   Normalized resource identifier, or None.
    action        Normalized action name from the domain action vocabulary.
                  Must not contain protocol-specific identifiers.
    context       Key/value context for policy conditions.
    payload       Original message payload, normalized to a plain dict.
                  The policy engine does not inspect this field. Protocol-
                  specific data belongs here, not in action or resource_id.
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

    Any object that exposes ``adapter_id``, ``protocol``, ``start()``, and
    ``stop()`` satisfies the interface. No class inheritance is required.

    Required behavior
    ─────────────────
    ``start()`` activates the adapter: opens connections, subscribes to topics,
    begins listening for protocol messages. Called once by the application during
    startup. Must not block indefinitely; long-running listener loops must run in
    a background thread or task.

    ``stop()`` deactivates the adapter: closes connections, drains pending
    messages, releases resources. Called by the application during graceful
    shutdown. Must not raise; exceptions from cleanup should be logged internally.
    After ``stop()`` returns, the adapter must not produce new ``NormalizedEvent``
    objects or call into the enforcement point.

    Forbidden during adapter lifecycle
    ───────────────────────────────────
    - Importing from ``basis_core.enforcement``. Adapters normalize; they do not
      evaluate authorization. The import boundary rule is enforced by
      ``tests/test_import_boundaries.py``.
    - Performing authorization evaluation inside ``start()``, ``stop()``, or
      any message-handling callback. Adapters produce ``NormalizedEvent`` objects
      and hand them to the enforcement point; they do not call
      ``PolicyEngine.evaluate()`` directly.
    - Changing ``adapter_id`` after ``start()`` has been called. The
      ``adapter_id`` is an external identifier that appears in audit records;
      it must be stable for the lifetime of a deployed adapter.

    Attributes
    ──────────
    adapter_id  Stable identifier. Appears in audit records and adapter registry
                entries. Must not change after the adapter is deployed to
                production — changing it orphans historical audit records.
    protocol    Human-readable protocol name for observability and diagnostics
                (e.g., "bacnet", "modbus-tcp", "mqtt"). Does not appear in
                policy rules or authorization decisions.
    """

    adapter_id: str
    protocol: str

    def start(self) -> None:
        """
        Activate the adapter.

        Called once during application startup. Must not block indefinitely.
        Must not call into the enforcement point or evaluate authorization.
        """
        ...

    def stop(self) -> None:
        """
        Deactivate the adapter.

        Called during graceful shutdown. Must not raise. Must not produce new
        NormalizedEvent objects after returning. Clean up all resources.
        """
        ...
