"""
basis_core.domain.identity — verified identity context for cross-boundary propagation.

IdentityContext is a structured, integrity-protected representation of a
verified subject's attributes. It is constructed after successful authentication
and carried through the request chain so that downstream components — including
enforcement points at interior trust boundaries — can make authorization
decisions based on the original requester's identity rather than the identity
of the forwarding component.

This is distinct from Subject. Subject is the domain model used within the
policy engine. IdentityContext is the wire-level representation used to carry
verified claims across trust boundaries. They share the same underlying data;
they serve different roles in the architecture.

Design notes
────────────
- IdentityContext is immutable once created.
- The ``token`` field holds the original integrity-protected token (e.g., a
  signed JWT). Downstream components verify the token rather than trusting
  the deserialized fields alone.
- ``propagated_from`` identifies the component that forwarded this context, if
  any. A gateway that forwards an operator's session attaches its own identity
  here so the propagation chain is auditable.
- This module defines the structure only. Token validation and context
  construction live in the authentication path (api/ or adapters/), not here.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel

from basis_core.domain.subject import Subject


class IdentityContext(BaseModel):
    """
    Verified identity context carried across trust boundaries.

    Fields
    ──────
    subject         The verified subject. Immutable once constructed.
    token           Original integrity-protected credential (JWT, signed token).
                    Downstream components verify this before trusting the fields.
    issued_at       Time the credential was issued (from the token).
    expires_at      Time the credential expires. None if no expiry is set.
    propagated_from Identity of the component that forwarded this context, if
                    the context was relayed through an intermediary.
    """

    subject:          Subject
    token:            str
    issued_at:        datetime
    expires_at:       Optional[datetime]  = None
    propagated_from:  Optional[str]       = None

    model_config = {"frozen": True}

    def is_expired(self, at: Optional[datetime] = None) -> bool:
        """Return True if the context has expired at the given time (default: now)."""
        if self.expires_at is None:
            return False
        check_time = at or datetime.utcnow()
        return check_time >= self.expires_at
