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
               Imports from domain/ only.

  enforcement/ The authorization enforcement boundary.
               Imports from policy/, audit/, decisions/, adapters/, domain/.
               EnforcementPoint connects policy evaluation and audit writing.

  adapters/    Adapter protocol and base utilities.
               Adapters normalize external representations into domain types.
               Implementations live outside this repository.
"""

__version__ = "0.1.0"
