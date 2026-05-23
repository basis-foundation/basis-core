"""
basis_core.policy.engine — policy evaluation engine and PolicyRule protocol.

PolicyEngine evaluates authorization requests by walking a list of PolicyRule
implementations under a deny-overrides semantics:

  1. Every rule is evaluated for the request.
  2. If any rule returns DENY, the engine returns DENY immediately (fail closed).
  3. If any rule returns ALLOW (and no DENY occurred), the engine returns ALLOW.
  4. If all rules return NOT_APPLICABLE, the engine returns NOT_APPLICABLE,
     which the EnforcementPoint treats as DENY (default deny).

This differs from chain-of-responsibility ("first match wins"). Deny-overrides
guarantees that an explicit prohibition cannot be bypassed by reordering rules.

PolicyOutcome
─────────────
Three values cover the full evaluation space:

  ALLOW          A rule positively permits the request.
  DENY           A rule positively prohibits the request.
  NOT_APPLICABLE This rule has no opinion; the request is outside its scope.
                 A rule must return NOT_APPLICABLE (not DENY) for requests it
                 does not recognize. Returning DENY for unknowns would block
                 actions that other rules are meant to allow.

Evaluation guarantees
─────────────────────
  Deny wins.       A single DENY overrides any number of ALLOWs.
  Default deny.    A request covered by no rule returns NOT_APPLICABLE, which
                   the EnforcementPoint resolves to DENY.
  Stateless.       The engine holds no mutable state after construction. It is
                   safe to share across requests and threads, provided the rule
                   implementations it holds are also stateless.
  Fail closed.     Exceptions inside rule evaluation cause the engine to return
                   DENY and log the failure.

Adding new rule types
─────────────────────
Implement the PolicyRule protocol:

    class MyRule:
        def evaluate(
            self,
            subject: Subject,
            action: str,
            resource_id: Optional[str] = None,
            identity_context: Optional[IdentityContext] = None,
            context: Optional[dict[str, Any]] = None,
        ) -> Decision:
            ...

Inject into the engine at construction:

    engine = PolicyEngine(policies=[
        MyRule(),
        RolePolicyRule(ROLE_TABLE),
    ])
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any, Optional, Protocol, runtime_checkable

from basis_core.domain.identity import IdentityContext
from basis_core.domain.subject import Subject

log = logging.getLogger("basis_core.policy.engine")


class PolicyOutcome(str, Enum):
    """
    The outcome produced by a single policy rule evaluation.

    ALLOW          The rule positively permits the request.
    DENY           The rule positively prohibits the request.
    NOT_APPLICABLE The rule has no opinion on this request. The engine
                   continues to the next rule. If all rules return
                   NOT_APPLICABLE, the engine applies default deny.
    """

    ALLOW          = "allow"
    DENY           = "deny"
    NOT_APPLICABLE = "not_applicable"


class Decision:
    """
    The outcome of a single policy rule evaluation, with context for audit records.

    Attributes
    ──────────
    outcome      PolicyOutcome value for this decision.
    reason       Human-readable explanation. Always present.
                 ALLOW: brief confirmation of what permitted the action.
                 DENY:  what was required vs. what the subject held.
                 NOT_APPLICABLE: why this rule does not apply.
    evaluated_by Name of the rule class that produced this decision.
                 Appears in audit records and debug output.
    allowed      Convenience property. True only when outcome is ALLOW.
    """

    __slots__ = ("outcome", "reason", "evaluated_by")

    def __init__(
        self,
        *,
        outcome: PolicyOutcome,
        reason: str,
        evaluated_by: str,
    ) -> None:
        self.outcome      = outcome
        self.reason       = reason
        self.evaluated_by = evaluated_by

    @property
    def allowed(self) -> bool:
        """True only when outcome is ALLOW."""
        return self.outcome == PolicyOutcome.ALLOW

    def __repr__(self) -> str:
        return (
            f"Decision({self.outcome.value.upper()}, "
            f"policy={self.evaluated_by!r}, "
            f"reason={self.reason!r})"
        )


@runtime_checkable
class PolicyRule(Protocol):
    """
    Interface all policy rule implementations must satisfy.

    evaluate() returns a Decision with an explicit PolicyOutcome:
      ALLOW          — this rule permits the request.
      DENY           — this rule prohibits the request.
      NOT_APPLICABLE — this rule does not cover this request; the engine
                       continues to the next rule.

    Rules must never return None. Use NOT_APPLICABLE for requests outside
    the rule's scope.

    Rules must be stateless. They must not modify system state, make
    network calls, or perform I/O during evaluate(). State needed for
    evaluation (e.g., a role table) is loaded at construction time.
    """

    def evaluate(
        self,
        subject: Subject,
        action: str,
        resource_id: Optional[str] = None,
        identity_context: Optional[IdentityContext] = None,
        context: Optional[dict[str, Any]] = None,
    ) -> Decision:
        ...


class PolicyEngine:
    """
    Evaluates authorization requests against a list of PolicyRule implementations
    using deny-overrides semantics.

    Usage
    ─────
        engine = PolicyEngine(policies=[RolePolicyRule(ROLE_TABLE)])
        decision = engine.evaluate(subject, "write:hvac:setpoint", "hvac:zone-a")
        if not decision.allowed:
            raise Forbidden(decision.reason)

    Evaluation order
    ────────────────
    1. All rules are evaluated for the request.
    2. If any rule returns DENY, that decision is returned immediately.
    3. If any rule returns ALLOW (and no DENY occurred), the first ALLOW is
       returned.
    4. If all rules return NOT_APPLICABLE, a NOT_APPLICABLE decision is returned.
       The EnforcementPoint treats NOT_APPLICABLE as DENY (default deny).

    The engine is stateless after construction.
    """

    def __init__(self, policies: list[PolicyRule]) -> None:
        self._policies = list(policies)
        log.info(
            "PolicyEngine initialized — %d rule(s): %s",
            len(self._policies),
            [type(p).__name__ for p in self._policies],
        )

    def evaluate(
        self,
        subject: Subject,
        action: str,
        resource_id: Optional[str] = None,
        identity_context: Optional[IdentityContext] = None,
        context: Optional[dict[str, Any]] = None,
    ) -> Decision:
        """
        Evaluate a subject's request to perform an action on a resource.

        Applies deny-overrides semantics across all registered rules.
        Returns NOT_APPLICABLE if no rule covers the action (which the
        EnforcementPoint resolves to DENY by default).
        """
        first_allow: Optional[Decision] = None

        for rule in self._policies:
            try:
                decision = rule.evaluate(
                    subject,
                    action,
                    resource_id=resource_id,
                    identity_context=identity_context,
                    context=context,
                )
            except Exception as exc:
                log.exception(
                    "PolicyEngine: rule %s raised during evaluation "
                    "(action=%r, subject=%s) — treating as DENY",
                    type(rule).__name__, action, str(subject),
                )
                return Decision(
                    outcome=PolicyOutcome.DENY,
                    reason=f"Rule evaluation error in {type(rule).__name__}: {exc}",
                    evaluated_by=type(rule).__name__,
                )

            if decision.outcome == PolicyOutcome.DENY:
                log.debug(
                    "rule=%-28s  subject=%-16s  action=%-32s  resource=%-16s  DENY",
                    decision.evaluated_by, str(subject), action, resource_id or "—",
                )
                return decision  # Deny overrides — stop immediately.

            if decision.outcome == PolicyOutcome.ALLOW and first_allow is None:
                first_allow = decision

        if first_allow is not None:
            log.debug(
                "rule=%-28s  subject=%-16s  action=%-32s  resource=%-16s  ALLOW",
                first_allow.evaluated_by, str(subject), action, resource_id or "—",
            )
            return first_allow

        # No rule handled this request — default deny.
        log.warning(
            "PolicyEngine: no rule covered action=%r subject=%s — NOT_APPLICABLE (default deny)",
            action, str(subject),
        )
        return Decision(
            outcome=PolicyOutcome.NOT_APPLICABLE,
            reason=(
                f"No policy rule is registered for action '{action}'. "
                "Every action that can be requested must be covered by at least "
                "one rule in the engine's chain. Default: deny."
            ),
            evaluated_by="PolicyEngine",
        )
