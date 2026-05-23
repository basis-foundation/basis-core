"""
basis-core — authorization foundation for operational systems.

Package layout:

  domain/      Canonical types: Subject, Resource, Action, Identity.
               No imports from other basis_core subpackages.
               Everything else may import from here.

  policy/      Policy engine and policy protocol.
               Imports from domain/ only.
               Evaluates (Subject, Resource, Action) → Decision.

  decisions/   Decision record types and the DecisionRequest/Response contract.
               Imports from domain/ only.

  audit/       Audit event types and the AuditWriter protocol.
               Imports from domain/ and decisions/ only.

  adapters/    Adapter protocol and base utilities.
               Adapters normalize external representations into domain types.
               Adapter implementations must not import from api/.

  api/         Entry points for exposing core logic over HTTP or other transports.
               Imports from all other subpackages.
               Infrastructure (FastAPI, databases, etc.) is introduced here only.
"""
