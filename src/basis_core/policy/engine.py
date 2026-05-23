"""
basis_core.policy.engine — policy evaluation engine and Policy protocol.

PolicyEngine evaluates authorization requests by walking a list of Policy
implementations in order. The first policy to return a non-None Decision wins.
If no policy handles the request, the engine returns a DENY decision. This
fail-closed default is intentional: an unrecognized action should never
silently succeed.

Chain-of-responsibility pattern
────────────────────────────────
Each Policy in the chain either:
  - Returns a Decision  → evaluation stops; this decision is used.
  - Returns None        → "I have no opinion; pass to the next policy."

Returning None is correct when a policy does not recognize the action or
does not apply to the given subject/resource combination. A policy must not
return DENY for requests it does not recognize; doing so prevents downstream
policies from allowing them.

Adding new policy types
───────────────────────
Prepend higher-precedence policies to the list. For example:

    PolicyEngine(policies=[
        EmergencyOverridePolicy(),   # Future: bypass normal policy in alarm state
        ZoneScopePolicy(),           # Future: zone-scoped role grants
        TimeWindowPolicy(),          # Future: time-of-day restrictions
        RolePolicy(ROLE_TABLE),      # Current: RBAC role assignments
    ])

The order determines which policy wins when multiple policies could apply.
"""

from __future__ import annotations

import logging
from typing import Optional, Protocol, runtime_checkable

from basis_core.domain.subject import Subject

log = logging.getLogger("basis_core.policy.engine")


class Decision:
    """
    The outcome of a single policy evaluation.

    Attributes
    ──────────
    allowed      True if the action is permitted.
    reason       Human-readable explanation. Always present.
                 ALLOW: brief confirmation of what permitted the action.
                 DENY:  what was required vs. what the subject held.
    evaluated_by Name of the Policy class that produced this decision.
                 Appears in audit records and debug output.
    """

    __slots__ = ("allowed", "reason", "evaluated_by")

    def __init__(self, *, allowed: bool, reason: str, evaluated_by: str) -> None:
        self.allowed      = allowed
        self.reason       = reason
        self.evaluated_by = evaluated_by

    def __repr__(self) -> str:
        verdict = "ALLOW" if self.allowed else "DENY"
        return (
            f"Decision({verdict}, "
            f"policy={self.evaluated_by!r}, "
            f"reason={self.reason!r})"
        )


@runtime_checkable
class Policy(Protocol):
    """
    Interface all policy implementations must satisfy.

    evaluate() returns:
      Decision  — this policy has an opinion (allow or deny).
      None      — this policy does not apply; pass to the next policy.
    """

    def evaluate(
        self,
        subject: Subject,
        action: str,
        resource_id: Optional[str] = None,
    ) -> Optional[Decision]:
        ...


class PolicyEngine:
    """
    Evaluates authorization requests against a list of Policy implementations.

    Usage
    ─────
        engine = PolicyEngine(policies=[RolePolicy(ROLE_TABLE)])
        decision = engine.evaluate(subject, "write:hvac:setpoint", "hvac:zone-a")
        if not decision.allowed:
            raise Forbidden(decision.reason)

    The engine is stateless after construction. It is safe to share across
    requests and threads, provided the Policy implementations it holds are
    also stateless (or safely concurrent).
    """

    def __init__(self, policies: list[Policy]) -> None:
        self._policies = list(policies)
        log.info(
            "PolicyEngine initialized — %d policy(ies): %s",
            len(self._policies),
            [type(p).__name__ for p in self._policies],
        )

    def evaluate(
        self,
        subject: Subject,
        action: str,
        resource_id: Optional[str] = None,
    ) -> Decision:
        """
        Evaluate a subject's request to perform an action on a resource.

        Returns the first non-None Decision from the chain, or a default
        DENY if no policy claims the action.
        """
        for policy in self._policies:
            decision = policy.evaluate(subject, action, resource_id)
            if decision is not None:
                log.debug(
                    "policy=%-24s  subject=%-16s  action=%-32s  resource=%-16s  %s",
                    decision.evaluated_by,
                    str(subject),
                    action,
                    resource_id or "—",
                    "ALLOW" if decision.allowed else "DENY",
                )
                return decision

        # Fail closed: no policy handled this action.
        reason = (
            f"No policy is registered for action '{action}'. "
            "Every action that can be requested must be covered by at least "
            "one policy in the engine's chain."
        )
        log.warning(
            "PolicyEngine: no policy covered action='%s' subject='%s'",
            action, str(subject),
        )
        return Decision(allowed=False, reason=reason, evaluated_by="PolicyEngine")
