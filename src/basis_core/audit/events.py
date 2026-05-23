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
  once the schema is in production use.
- event_type distinguishes audit trail categories so consumers can filter
  without parsing free-text fields.
- schema_version identifies the AuditEvent schema revision. Increment it
  when fields are added so consumers can detect which fields are present.

Validation rules
────────────────
- ``event_id`` must be non-empty (auto-generated UUID v4 by default).
- ``action`` must be non-empty.
- ``timestamp`` must be timezone-aware. The default factory produces UTC.

Correlation fields
──────────────────
Three identifiers serve different correlation purposes:

  event_id       Unique identifier for this audit record.
  request_id     Links to the DecisionRequest and DecisionResponse.
  decision_id    Identifies the decision itself. Defaults to request_id when
                 not separately assigned. Use when the application assigns its
                 own decision identifiers.
  correlation_id Optional caller-provided identifier for distributed tracing
                 (e.g., an HTTP request trace ID or a batch job ID).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator

from basis_core.audit.trace import DecisionTrace

# Schema version for this AuditEvent definition. Increment when fields are added.
AUDIT_SCHEMA_VERSION = "1.1"


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

    Identification and correlation
    ──────────────────────────────
    event_id        Unique identifier for this audit record. UUID v4 auto-generated.
    event_type      Category of the event.
    timestamp       UTC time the event occurred. Must be timezone-aware.
    schema_version  AuditEvent schema revision in effect when this record was
                    written. Used by consumers to determine field availability.

    request_id      DecisionRequest.request_id — links this record to the request
                    and response that triggered it.
    decision_id     Identifier for the decision itself. Defaults to request_id
                    when not separately assigned by the application.
    correlation_id  Optional caller-provided trace ID for cross-system correlation
                    (e.g., HTTP request ID, batch job ID).

    Subject context
    ───────────────
    subject_id      Stable identifier of the subject. None for system events.
    subject_name    Human-readable subject label.
    subject_type    SubjectType value (e.g., "human", "device").
    subject_roles   Roles held by the subject at the time of the event.

    Resource and action
    ───────────────────
    action          Action name (e.g., "write:hvac:setpoint"). Non-empty.
    resource_id     Normalized resource identifier, if applicable.
    resource_type   ResourceType value (e.g., "hvac", "sensor").

    Decision context
    ────────────────
    outcome         ALLOWED, DENIED, or ERROR. None for non-decision events.
    reason          Human-readable explanation of the outcome.
    evaluated_by    Name of the rule that produced the final decision.
    policy_version  Version of the policy set in effect at evaluation time.
    matched_rules   Names of rules that returned allow or deny (not not_applicable).
                    Empty for non-decision events or when no rules matched.

    Traceability
    ────────────
    trace           Per-rule evaluation history, if available. Explains why the
                    decision was produced. Optional — events are valid without it.

    Miscellaneous
    ─────────────
    detail          Arbitrary key/value context: command parameters, error info,
                    adapter metadata, etc.
    """

    # — Identification —
    event_id:       str            = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type:     AuditEventType = AuditEventType.AUTHORIZATION_DECISION
    timestamp:      datetime       = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    schema_version: str            = AUDIT_SCHEMA_VERSION

    # — Correlation —
    request_id:     Optional[str]  = None
    decision_id:    Optional[str]  = None
    correlation_id: Optional[str]  = None

    # — Subject —
    subject_id:     Optional[str]  = None
    subject_name:   Optional[str]  = None
    subject_type:   Optional[str]  = None
    subject_roles:  list[str]      = []

    # — Resource and action —
    action:         str
    resource_id:    Optional[str]  = None
    resource_type:  Optional[str]  = None

    # — Decision —
    outcome:        Optional[AuditOutcome]  = None
    reason:         Optional[str]           = None
    evaluated_by:   Optional[str]           = None
    policy_version: Optional[str]           = None
    matched_rules:  list[str]               = []

    # — Traceability —
    trace:          Optional[DecisionTrace] = None

    # — Miscellaneous —
    detail:         dict           = {}

    model_config = {"frozen": True}

    @field_validator("event_id", mode="after")
    @classmethod
    def event_id_must_not_be_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("event_id must not be empty or whitespace-only")
        return v

    @field_validator("action", mode="after")
    @classmethod
    def action_must_not_be_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("action must not be empty or whitespace-only")
        return v

    @field_validator("timestamp", mode="after")
    @classmethod
    def timestamp_must_be_tz_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError(
                "AuditEvent.timestamp must be timezone-aware. "
                "Use datetime.now(timezone.utc) or attach tzinfo explicitly."
            )
        return v
