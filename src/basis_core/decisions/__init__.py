"""
basis_core.decisions — decision request and response contract.

This package defines the data contract for the authorization boundary:
what goes in, and what comes out. It is used by enforcement points,
API handlers, and any other component that submits authorization requests
or interprets decisions.

Contents
────────
  models.py    DecisionRequest, DecisionResponse, DecisionOutcome, FailureReason.
               These are the normalized structures that cross the
               enforcement boundary. They correspond to the JSON schemas
               in schemas/decision-request.schema.json and
               schemas/decision-response.schema.json.

Public API
──────────
All stable public symbols are available directly from this package.
See ``docs/public-api.md`` for the full inventory and stability tiers.
"""

from basis_core.decisions.models import (
    DecisionOutcome,
    DecisionRequest,
    DecisionResponse,
    FailureReason,
)

__all__ = [
    "DecisionRequest",
    "DecisionResponse",
    "DecisionOutcome",
    "FailureReason",
]
