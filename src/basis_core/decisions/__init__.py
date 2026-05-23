"""
basis_core.decisions — decision request and response contract.

This package defines the data contract for the authorization boundary:
what goes in, and what comes out. It is used by enforcement points,
API handlers, and any other component that submits authorization requests
or interprets decisions.

Contents
────────
  models.py    DecisionRequest, DecisionResponse, DecisionOutcome.
               These are the normalized structures that cross the
               enforcement boundary. They correspond to the JSON schemas
               in schemas/decision-request.schema.json and
               schemas/decision-response.schema.json.
"""
