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
"""
