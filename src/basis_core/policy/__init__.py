"""
basis_core.policy — policy evaluation engine and policy protocol.

This package answers the authorization question:
  "May subject S perform action A on resource R?"

It imports from domain/ only. It has no knowledge of HTTP, databases,
protocol adapters, or infrastructure.

Contents
────────
  engine.py    PolicyEngine and the Policy protocol.
               Chain-of-responsibility evaluation: first policy to return a
               Decision wins; uncovered actions fail closed (deny).

  rules.py     Concrete policy implementations.
               RolePolicy: RBAC-style action → required roles mapping.
               Future: AttributePolicy, TimeWindowPolicy, ZoneScopePolicy.
"""
