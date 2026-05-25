"""
basis_core.audit.writer — AuditWriter protocol and a no-op reference implementation.

Enforcement points and the policy engine call AuditWriter.write(). They do not
depend on where records go. Concrete backends (append-only file, structured log
pipeline, time-series store, etc.) implement this protocol and are provided
through application configuration.

AuditWriter is a Protocol, not an abstract base class. Any object that
implements write(event: AuditEvent) -> None satisfies the interface, regardless
of inheritance. This keeps the audit path decoupled from any specific backend
technology.

NullAuditWriter
───────────────
Discards all events. Suitable for:
  - Unit tests that do not need to verify audit output.
  - Development environments where audit persistence is not yet configured.

Not suitable for any production context. A NullAuditWriter leaves no record
of authorization decisions.

LogAuditWriter
──────────────
Writes events as structured JSON to a standard Python logger. Suitable for:
  - Development and integration testing.
  - Environments where a log aggregation pipeline consumes stdout/stderr.

Not a substitute for append-only, integrity-protected storage in production.
"""

from __future__ import annotations

import json
import logging
from typing import Protocol, runtime_checkable

from basis_core.audit.events import AuditEvent

log = logging.getLogger("basis_core.audit")


@runtime_checkable
class AuditWriter(Protocol):
    """
    Interface for audit record persistence backends.

    Any object with a ``write()`` method matching this signature satisfies the
    interface. No class inheritance is required.

    Required behavior
    ─────────────────
    ``write()`` must not raise. If the backend encounters an error (I/O failure,
    serialization error, network timeout), it must catch the exception internally
    and log it. The ``EnforcementPoint`` catches exceptions from ``write()`` as a
    last resort, but ``AuditWriter`` implementations must not depend on that: a
    raised exception produces an application log entry rather than a proper
    audit-failure record.

    ``write()`` must not mutate the event. ``AuditEvent`` is a frozen Pydantic
    model; mutation attempts will raise ``ValidationError``. Implementations that
    need to transform the event for storage must work from ``event.model_dump()``
    or a serialized copy, not from the event object itself.

    ``write()`` must not influence the authorization decision. It must not call
    back into the ``PolicyEngine`` or ``EnforcementPoint``, modify shared
    application state, or raise exceptions that could alter the caller's control
    flow.

    Purpose and scope
    ─────────────────
    Audit is evidence, not enforcement. The decision has already been made by the
    ``PolicyEngine`` before ``write()`` is called. The writer's responsibility is
    to record what happened. A write failure does not reverse the decision — see
    ``docs/failure-modes.md`` for the governing rationale.

    Ordering expectations
    ─────────────────────
    The ``EnforcementPoint`` calls ``write()`` exactly once per evaluated request
    (excluding malformed requests that fail pre-policy validation). Writers may
    not assume that events arrive in timestamp order; concurrent requests may
    produce out-of-order calls.

    What implementations may assume
    ────────────────────────────────
    - ``event`` is a complete, frozen ``AuditEvent`` with a non-empty
      ``event_id``, a timezone-aware ``timestamp``, and a non-empty ``action``.
    - ``event.outcome`` accurately reflects the authorization decision that was
      made for the request identified by ``event.request_id``.
    - The same ``event_id`` will not be passed to ``write()`` twice in a
      single-process lifetime (though writers that persist across restarts must
      handle duplicate delivery at the storage layer).
    """

    def write(self, event: AuditEvent) -> None:
        """
        Persist an audit event.

        Must not raise. Must not mutate ``event``. Must not affect the
        authorization outcome. If persistence fails, catch the exception
        internally and log it.
        """
        ...


class NullAuditWriter:
    """Discards all events. For tests and unconfigured environments only."""

    def write(self, event: AuditEvent) -> None:
        pass


class LogAuditWriter:
    """
    Writes audit events as structured JSON to a Python logger.

    Parameters
    ──────────
    logger   Logger instance. Defaults to "basis_core.audit".
    level    Log level for audit records. Defaults to INFO.
    """

    def __init__(
        self,
        logger: logging.Logger | None = None,
        level: int = logging.INFO,
    ) -> None:
        self._log = logger or log
        self._level = level

    def write(self, event: AuditEvent) -> None:
        try:
            record = event.model_dump(mode="json")
            self._log.log(self._level, json.dumps(record))
        except Exception:
            # Never let an audit write failure propagate to the caller.
            self._log.exception(
                "AuditWriter: failed to serialize event event_id=%s",
                getattr(event, "event_id", "unknown"),
            )
