"""
basis_core.audit.events — normalized audit event structure.

An AuditEvent is the canonical record of any security-relevant occurrence:
an authorization decision, a policy change, an identity lifecycle event, or
an emergency override. Every event that matters for accountability, compliance,
or incident investigation is expressed as an AuditEvent.

Design constraints
──────────────────
- Events are immutable once created. No field is modified after construction.
- Events carry the full context needed to interpret them independently:
  who, what resource, what action, what outcome, which policy, when.
- The event schema is stable. Fields are added, never removed or renamed,
  once the schema is in production use. Removing a field breaks any consumer
  that depends on it and any query that references it.
- event_type distinguishes the audit trail categories so consumers can filter
  without parsing free-text fields.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class AuditEventType(str, Enum):
    """High-level category for an audit record."""

    AUTHORIZATION_DECISION = "authorization_decision"
    POLICY_CHANGE          = "policy_change"
    IDENTITY_EVENT         = "identity_event"
    EMERGENCY_OVERRIDE     = "emergency_override"
    ADAPTER_EVENT          = "adapter_event"
    SYSTEM_EVENT           = "system_event"


class AuditOutcome(str, Enum):
    """Outcome recorded for authorization decision events."""

    ALLOWED = "allowed"
    DENIED  = "denied"
    ERROR   = "error"


class AuditEvent(BaseModel):
    """
    Normalized record of a security-relevant system event.

    Every field that appears here appears verbatim in stored records. Field
    names are treated as stable external identifiers once in production use.

    Fields
    ──────
    event_id        Unique identifier for this record. UUID v4.
    event_type      Category of the event.
    timestamp       UTC time the event occurred (not the time it was written).

    subject_id      Stable identifier of the subject. None for system events.
    subject_name    Human-readable subject label.
    subject_type    SubjectType value (e.g., "human", "device").
    subject_roles   Roles held by the subject at the time of the event.

    action          Action name (e.g., "write:hvac:setpoint").
    resource_id     Normalized resource identifier, if applicable.
    resource_type   ResourceType value (e.g., "hvac", "sensor").

    outcome         ALLOWED, DENIED, or ERROR.
    reason          Human-readable explanation of the outcome.
    evaluated_by    Name of the policy that produced the decision.
    policy_version  Version of the policy set in effect at evaluation time.

    request_id      DecisionRequest.request_id for correlation.
    detail          Arbitrary key/value context. Command parameters, error
                    information, adapter metadata, etc.
    """

    event_id:       str            = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type:     AuditEventType = AuditEventType.AUTHORIZATION_DECISION
    timestamp:      datetime       = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    subject_id:     Optional[str]       = None
    subject_name:   Optional[str]       = None
    subject_type:   Optional[str]       = None
    subject_roles:  list[str]           = []

    action:         str
    resource_id:    Optional[str]       = None
    resource_type:  Optional[str]       = None

    outcome:        Optional[AuditOutcome] = None
    reason:         Optional[str]          = None
    evaluated_by:   Optional[str]          = None
    policy_version: Optional[str]          = None

    request_id:     Optional[str]          = None
    detail:         dict                   = {}
