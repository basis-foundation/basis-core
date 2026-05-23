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
    """Interface for audit record persistence backends."""

    def write(self, event: AuditEvent) -> None:
        """Persist an audit event. Must not raise on write failure."""
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
        self._log   = logger or log
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
