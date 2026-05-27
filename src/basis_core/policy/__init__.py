"""
basis_core.policy — policy evaluation engine and policy protocol.

This package answers the authorization question:
  "May subject S perform action A on resource R?"

It imports from domain/ only. It has no knowledge of HTTP, databases,
protocol adapters, or infrastructure.

Contents
────────
  engine.py    PolicyEngine, PolicyRule (Protocol), Decision, PolicyOutcome.
               Deny-overrides evaluation: a single DENY overrides all ALLOWs.

  rules.py     Concrete policy implementations.
               RolePolicyRule:         RBAC-style action → required roles mapping.
               ResourceTypePolicyRule: constrains permitted ResourceType targets.
               ActionPolicyRule:       explicit per-action allow/deny table.

Public API
──────────
All stable public symbols are available directly from this package.
See ``docs/public-api.md`` for the full inventory and stability tiers.
"""

from basis_core.policy.engine import Decision, PolicyEngine, PolicyOutcome, PolicyRule
from basis_core.policy.rules import ActionPolicyRule, ResourceTypePolicyRule, RolePolicyRule

__all__ = [
    # engine
    "PolicyEngine",
    "PolicyRule",
    "Decision",
    "PolicyOutcome",
    # built-in rule implementations
    "RolePolicyRule",
    "ResourceTypePolicyRule",
    "ActionPolicyRule",
]
