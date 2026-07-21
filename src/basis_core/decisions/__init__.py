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

Operation-aware public API (v0.2.0)
────────────────────────────────────
Additive sibling surface: ``OperationAwareDecisionRequest`` (the richer
operation-aware request, coexisting with ``DecisionRequest`` unchanged) and
its closed vocabularies — ``OperationIntent``, ``OperationAwareFailureReason``,
``OperationAwareEvaluationStatus``, ``OperationAwareDecisionOutcome``. The
latter three are shared operation-aware evaluation-result vocabulary, also
consumed by ``policy``, ``audit``, and ``evaluation`` internally. See
``docs/public-api.md``'s "Operation-aware public API (v0.2.0)" section.
"""

from basis_core.decisions.models import (
    DecisionOutcome,
    DecisionRequest,
    DecisionResponse,
    FailureReason,
)
from basis_core.decisions.operation_aware import (
    OperationAwareDecisionOutcome,
    OperationAwareDecisionRequest,
    OperationAwareEvaluationStatus,
    OperationAwareFailureReason,
    OperationIntent,
)

__all__ = [
    "DecisionRequest",
    "DecisionResponse",
    "DecisionOutcome",
    "FailureReason",
    # operation-aware (v0.2.0)
    "OperationAwareDecisionRequest",
    "OperationIntent",
    "OperationAwareFailureReason",
    "OperationAwareEvaluationStatus",
    "OperationAwareDecisionOutcome",
]
