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

Operation-aware public API (v0.2.0)
────────────────────────────────────
Additive sibling surface: the structured operation-aware policy data models
— ``PolicyCondition``, ``OperationAwarePolicyRule`` (a distinct, unrelated
*data model*; ``PolicyRule`` above remains the v0.1.0 extension-point
``Protocol``, unchanged), ``OperationAwarePolicyMatch``, ``RuleEffect``,
``PolicyBundle``, and ``PolicyBundleScope``. These are structured data a
bundle author authors, not a new executable extension point. Internal
evaluators, selectors, operators, aggregation, and validation helpers remain
internal. See ``docs/public-api.md``'s "Operation-aware public API (v0.2.0)"
section.
"""

from basis_core.policy.engine import Decision, PolicyEngine, PolicyOutcome, PolicyRule
from basis_core.policy.operation_aware.bundle import PolicyBundle, PolicyBundleScope
from basis_core.policy.operation_aware.condition import PolicyCondition
from basis_core.policy.operation_aware.rule import (
    OperationAwarePolicyMatch,
    OperationAwarePolicyRule,
    RuleEffect,
)
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
    # operation-aware (v0.2.0) — structured policy data models
    "PolicyCondition",
    "OperationAwarePolicyRule",
    "OperationAwarePolicyMatch",
    "RuleEffect",
    "PolicyBundle",
    "PolicyBundleScope",
]
