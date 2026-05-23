"""
basis_core.decisions.models — the authorization boundary data contract.

DecisionRequest and DecisionResponse are the normalized structures that cross
the enforcement boundary. Enforcement points construct a DecisionRequest from
whatever representation the upstream component provided, submit it to the
policy engine, and receive a DecisionResponse.

Neither structure contains protocol-specific fields. Protocol adapters are
responsible for constructing a DecisionRequest from a normalized event before
the enforcement point evaluates it. The policy engine never sees raw protocol
frames.

DecisionOutcome
───────────────
Three values cover the full decision space:

  ALLOW          The request is permitted. Enforcement point proceeds.
  DENY           The request is not permitted. Enforcement point rejects.
  NOT_APPLICABLE No applicable policy was found. Enforcement point applies
                 its configured default (typically DENY).

The distinction between DENY and NOT_APPLICABLE is useful for diagnosis:
DENY means a policy evaluated the request and refused it; NOT_APPLICABLE
means the request fell outside the scope of any registered policy. Both
should be audited, but they indicate different operational conditions.

Validation rules
────────────────
- ``subject_id`` must be non-empty.
- ``action`` must be non-empty and match the naming convention:
  ``{verb}:{domain}[:{object}]`` — colon-separated, lowercase segments,
  at least two segments.
- ``subject_roles`` are normalized on construction: whitespace stripped,
  empty strings discarded, duplicates removed, result sorted.
- ``timestamp`` must be timezone-aware. The default factory produces UTC.
  Explicitly constructed timestamps must include tzinfo.
- ``request_id`` and ``evaluated_by`` in DecisionResponse must be non-empty.
- ``reason`` in DecisionResponse must be non-empty.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field, field_validator

# Action names follow the pattern: two or more colon-separated lowercase segments.
# Each segment: starts with a letter, followed by letters/digits/hyphens/underscores.
_ACTION_RE = re.compile(r"^[a-z][a-z0-9_-]*(:[a-z][a-z0-9_-]*)+$")


class DecisionOutcome(str, Enum):
    """
    Explicit set of possible authorization decision outcomes.

    Using an enum (rather than a plain string) makes exhaustive handling
    enforceable by type checkers and prevents callers from accidentally
    comparing against a misspelled literal.
    """

    ALLOW = "allow"
    DENY = "deny"
    NOT_APPLICABLE = "not_applicable"


class FailureReason(str, Enum):
    """
    Reason code for a safe-deny produced by an enforcement boundary failure.

    These values are set on DecisionResponse.failure_reason when the denial
    was not produced by normal policy evaluation but by a system-level failure.
    None means the decision was produced by normal policy evaluation.

    MALFORMED_REQUEST   The request could not be parsed or validated. The
                        enforcement point never reached policy evaluation.
    POLICY_ERROR        An exception was raised during policy rule evaluation.
                        The policy engine failed closed: DENY returned.
    AUDIT_ERROR         The audit write failed after a valid decision was made.
                        The decision itself is unchanged; this code is available
                        for future use where the EP could signal the audit gap.
    INTERNAL_ERROR      An unexpected exception occurred inside the enforcement
                        point before or after policy evaluation.
    """

    MALFORMED_REQUEST = "malformed_request"
    POLICY_ERROR = "policy_error"
    AUDIT_ERROR = "audit_error"
    INTERNAL_ERROR = "internal_error"


class DecisionRequest(BaseModel):
    """
    A normalized authorization request submitted to the policy engine.

    Fields
    ──────
    request_id    Unique identifier for correlation with the audit record.
                  Auto-generated if not provided. Must be non-empty if set.
    subject_id    Stable identifier of the requesting subject. Non-empty.
    subject_roles Role names held by the subject at request time.
                  Normalized: sorted, deduplicated, whitespace-stripped.
    subject_attrs Additional subject attributes for ABAC conditions.
    resource_id   Normalized resource identifier (e.g., "hvac:zone-a").
                  Optional. None when the request is not resource-specific.
    action        Action name, e.g. "write:hvac:setpoint". Non-empty. Must
                  follow the "{verb}:{domain}[:{object}]" convention.
    context       Arbitrary key/value context for policy conditions.
                  Examples: ``{"site": "bldg-a", "maintenance_window": "true"}``
    timestamp     Time the request was constructed. Must be timezone-aware.
    """

    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    subject_id: str
    subject_roles: list[str] = []
    subject_attrs: dict[str, str] = {}
    resource_id: str | None = None
    action: str
    context: dict[str, str] = {}
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("request_id", "subject_id", mode="after")
    @classmethod
    def ids_must_not_be_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("must not be empty or whitespace-only")
        return v

    @field_validator("action", mode="after")
    @classmethod
    def validate_action_format(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("action must not be empty or whitespace-only")
        if not _ACTION_RE.match(v):
            raise ValueError(
                f"action {v!r} does not match the required format "
                "'{verb}:{domain}[:{object}]' (e.g. 'write:hvac:setpoint', "
                "'read:audit:log'). Segments must be lowercase and separated by colons."
            )
        return v

    @field_validator("subject_roles", mode="before")
    @classmethod
    def normalize_roles(cls, v: object) -> list[str]:
        """Strip whitespace, discard empty strings, deduplicate, sort."""
        if not isinstance(v, list):
            return v  # type: ignore[return-value]
        return sorted({r.strip() for r in v if isinstance(r, str) and r.strip()})

    @field_validator("timestamp", mode="after")
    @classmethod
    def timestamp_must_be_tz_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError(
                "DecisionRequest.timestamp must be timezone-aware. "
                "Use datetime.now(timezone.utc) or attach tzinfo explicitly."
            )
        return v


class DecisionResponse(BaseModel):
    """
    The result of an authorization evaluation.

    Fields
    ──────
    request_id      Echoes the request_id from the DecisionRequest.
                    Non-empty; used for audit correlation.
    outcome         Explicit DecisionOutcome value. Never a bare string.
    reason          Human-readable explanation of the outcome. Non-empty.
                    ALLOW: brief confirmation of what permitted the action.
                    DENY:  what was required vs. what the subject held.
    evaluated_by    Name of the policy that produced this decision. Non-empty.
                    Appears in audit records.
    policy_version  Version identifier of the policy set in effect at
                    evaluation time. Used for audit correlation.
    failure_reason  Set when the denial was caused by an enforcement boundary
                    failure rather than normal policy evaluation. None for
                    decisions produced by the policy engine. See FailureReason.
    timestamp       Time the decision was produced. Timezone-aware.
    """

    request_id: str
    outcome: DecisionOutcome
    reason: str
    evaluated_by: str
    policy_version: str | None = None
    failure_reason: FailureReason | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("request_id", "reason", "evaluated_by", mode="after")
    @classmethod
    def must_not_be_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("must not be empty or whitespace-only")
        return v

    @field_validator("timestamp", mode="after")
    @classmethod
    def timestamp_must_be_tz_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError(
                "DecisionResponse.timestamp must be timezone-aware. "
                "Use datetime.now(timezone.utc) or attach tzinfo explicitly."
            )
        return v

    @property
    def allowed(self) -> bool:
        """Convenience accessor. True only when outcome is ALLOW."""
        return self.outcome == DecisionOutcome.ALLOW
