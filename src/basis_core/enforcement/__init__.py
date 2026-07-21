"""
basis_core.enforcement — the kernel's authorization enforcement boundary.

This package contains the EnforcementPoint: the single component that connects
an incoming normalized request to the policy engine and the audit writer.

Nothing in domain/, policy/, decisions/, audit/, or adapters/ imports from
enforcement/. The enforcement package sits at the top of the kernel import
hierarchy and depends inward on policy, decisions, audit, and domain.

Contents
────────
  enforcement.py   EnforcementPoint — submits DecisionRequests to the
                   PolicyEngine, records decisions in the audit log, and
                   returns DecisionResponses. Fail-closed on all error paths.

Public API
──────────
``EnforcementPoint`` is the sole public export of this package for v0.1.
See ``docs/public-api.md`` for the full inventory and stability tiers.

Operation-aware public API (v0.2.0)
────────────────────────────────────
Additive sibling surface: ``OperationAwareEnforcementPoint`` (composes
operation-aware evaluation into a fail-closed ``evaluate()`` that never
raises), its immutable result carrier ``OperationAwareEnforcementResult``,
and the enforcement-only ``EnforcementDisposition`` vocabulary. Neither
modifies, subclasses, or shares implementation with ``EnforcementPoint``
above; both coexist. See ``docs/public-api.md``'s "Operation-aware public
API (v0.2.0)" section.
"""

from basis_core.enforcement.enforcement import EnforcementPoint
from basis_core.enforcement.operation_aware import (
    EnforcementDisposition,
    OperationAwareEnforcementPoint,
    OperationAwareEnforcementResult,
)

__all__ = [
    "EnforcementPoint",
    # operation-aware (v0.2.0)
    "EnforcementDisposition",
    "OperationAwareEnforcementPoint",
    "OperationAwareEnforcementResult",
]
