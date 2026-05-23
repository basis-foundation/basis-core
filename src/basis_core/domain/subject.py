"""
basis_core.domain.subject — the identity of any entity performing an action.

A Subject is a normalized, immutable representation of who or what initiated
an authorization request. It is the single translation point between raw
credential representations (JWT claims, device certificates, service tokens)
and the domain model the policy engine reasons about.

SubjectType documents the intended population of principals in an OT system:
human operators, field devices, service processes, protocol gateways, and
autonomous software agents. Only some of these are wired to authentication
paths in any given deployment; the others exist so the model can accommodate
them without a breaking change when they are introduced.

Design notes
────────────
- Subject is frozen (immutable). It is constructed once during credential
  validation and passed through the authorization path without modification.
- The policy layer works with Subject fields directly. It never receives raw
  credential payloads.
- subject_from_jwt() is the reference translation function for OIDC/JWT-based
  human subjects. Other SubjectType values will have analogous constructors
  when their authentication paths are wired.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel


class SubjectType(str, Enum):
    """Classification of who or what is performing an action."""

    HUMAN   = "human"    # Authenticated human operator via OIDC/JWT
    DEVICE  = "device"   # Physical OT device with its own identity credential
    SERVICE = "service"  # Internal service or adapter process
    GATEWAY = "gateway"  # Protocol bridge (BACnet/IP, Modbus TCP, OPC-UA, …)
    AGENT   = "agent"    # Autonomous software agent acting on behalf of a subject


class Subject(BaseModel):
    """
    The normalized identity of any entity performing an action in BASIS.

    Fields
    ──────
    id      Stable unique identifier. For HUMAN subjects: JWT ``sub`` claim.
    name    Human-readable label. For HUMAN subjects: ``preferred_username``.
    type    SubjectType value. Determines which authentication path applied.
    roles   Granted role names. For HUMAN subjects: from ``realm_access.roles``.
    attrs   Arbitrary additional claims useful for ABAC policy conditions.
            Examples: ``{"site": "building-a", "clearance": "l2"}``
    """

    id:    str
    name:  str
    type:  SubjectType = SubjectType.HUMAN
    roles: list[str]   = []
    attrs: dict[str, str] = {}

    model_config = {"frozen": True}

    def has_role(self, *roles: str) -> bool:
        """Return True if the subject holds at least one of the given roles."""
        return bool(set(self.roles) & set(roles))

    def __str__(self) -> str:
        return f"{self.type.value}:{self.name}"


def subject_from_jwt(payload: dict) -> Subject:
    """
    Construct a Subject from a decoded OIDC/JWT token payload.

    This function is the canonical translation boundary between raw JWT claims
    and the basis_core domain model. All downstream code receives a Subject;
    none receives a raw payload dict.

    Expected input (Keycloak-style JWT):
        {
          "sub": "a7b8c9d0-...",
          "preferred_username": "alice",
          "realm_access": {"roles": ["operator"]},
          "email": "alice@example.com"   # optional
        }

    Other SubjectType values are constructed directly (not via this function)
    because their source representations differ from JWT claims.
    """
    roles: list[str] = payload.get("realm_access", {}).get("roles", [])
    attrs: dict[str, str] = {}
    if email := payload.get("email"):
        attrs["email"] = email

    return Subject(
        id=payload.get("sub", "unknown"),
        name=payload.get("preferred_username", "unknown"),
        type=SubjectType.HUMAN,
        roles=roles,
        attrs=attrs,
    )
