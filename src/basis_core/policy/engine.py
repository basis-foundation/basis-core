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
from typing import Any, Protocol, runtime_checkable

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

    ALLOW = "allow"
    DENY = "deny"
    NOT_APPLICABLE = "not_applicable"


class Decision:
    """
    The outcome of a policy evaluation, with context for audit records.

    Attributes
    ──────────
    outcome          PolicyOutcome value for this decision.
    reason           Human-readable explanation. Always present.
                     ALLOW: brief confirmation of what permitted the action.
                     DENY:  what was required vs. what the subject held.
                     NOT_APPLICABLE: why this rule does not apply.
    evaluated_by     Name of the rule class that produced this decision.
                     Appears in audit records and debug output.
    evaluated_rules  Ordered list of per-rule evaluation records collected by
                     the PolicyEngine. Each entry is a (rule_name, outcome_value,
                     reason) tuple using plain strings for outcome_value so that
                     audit consumers do not need to import PolicyOutcome.
                     Empty for Decision objects created directly by rules.
    is_error         True when this decision was produced by the engine catching
                     an exception inside a rule, rather than by a normal rule
                     evaluation path. The enforcement point uses this flag to
                     sanitize the caller-visible reason and set FailureReason.
    allowed          Convenience property. True only when outcome is ALLOW.
    """

    __slots__ = ("outcome", "reason", "evaluated_by", "evaluated_rules", "is_error")

    def __init__(
        self,
        *,
        outcome: PolicyOutcome,
        reason: str,
        evaluated_by: str,
        evaluated_rules: list[tuple[str, str, str]] | None = None,
        is_error: bool = False,
    ) -> None:
        self.outcome = outcome
        self.reason = reason
        self.evaluated_by = evaluated_by
        self.evaluated_rules = evaluated_rules or []
        self.is_error = is_error

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

    Any object with an ``evaluate()`` method matching this signature satisfies
    the interface. No class inheritance is required.

    Required behavior
    ─────────────────
    ``evaluate()`` must always return a ``Decision`` with an explicit
    ``PolicyOutcome``. It must never return ``None`` and must never raise
    without catching — the engine catches unhandled exceptions and treats them
    as DENY with ``is_error=True``, but relying on this is incorrect rule design.

    Use ``NOT_APPLICABLE`` for requests outside the rule's scope. A rule must
    not return ``DENY`` for actions it simply does not recognize; that would
    prevent downstream rules from allowing them and would violate deny-overrides
    composition.

    Populate ``evaluated_by`` with a stable, non-empty identifier (typically the
    class name or a constructor-configured rule name). This value appears verbatim
    in ``DecisionResponse.evaluated_by`` and in audit records. It must not be
    empty and must not change between calls on the same instance.

    Populate ``reason`` with a non-empty, human-readable explanation. The reason
    appears in ``DecisionResponse.reason`` and audit records. Raw exception text,
    stack traces, and internal implementation details must not appear in ``reason``.

    Statefulness and thread safety
    ──────────────────────────────
    Rules must be stateless at evaluation time: ``evaluate()`` must not modify
    any instance attribute, write to external state, or produce side effects
    beyond the returned ``Decision``. State needed for evaluation (role tables,
    resource configurations, action allowlists) must be loaded at construction
    time and held as an immutable reference.

    A ``PolicyEngine`` instance is designed to be shared across concurrent
    requests. Rules registered in the engine must be safe for concurrent use —
    which follows naturally from the statelessness requirement.

    Forbidden side effects during evaluate()
    ─────────────────────────────────────────
    - Network calls, database queries, or file I/O.
    - Modifying the ``Subject``, ``context``, or any other argument received.
    - Calling ``EnforcementPoint.evaluate()`` recursively or invoking another
      ``PolicyEngine`` (would violate import boundaries and create recursion).
    - Sleeping, blocking on a lock, or introducing latency beyond in-process
      computation.
    - Importing from ``basis_core.enforcement`` (violates import boundary rules).

    What rules may assume about inputs
    ───────────────────────────────────
    - ``subject`` is a frozen, validated ``Subject`` instance. Its fields will
      not change during the call.
    - ``action`` is a non-empty string validated against the
      ``{verb}:{domain}[:{object}]`` format.
    - ``resource_id``, when not None, has been validated against the
      ``{type}:{qualifier}`` format.
    - ``context``, when not None, is a plain ``dict[str, str]``; treat as
      read-only.
    - The engine calls rules in registration order and never reorders them.
    """

    def evaluate(
        self,
        subject: Subject,
        action: str,
        resource_id: str | None = None,
        identity_context: IdentityContext | None = None,
        context: dict[str, Any] | None = None,
    ) -> Decision:
        """
        Evaluate whether the subject is permitted to perform the action.

        Parameters
        ──────────
        subject          Frozen, validated identity of the requesting entity.
        action           Validated action name (e.g. "write:hvac:setpoint").
        resource_id      Validated resource identifier, or None for
                         resource-independent requests.
        identity_context Verified identity context carrying additional claims,
                         or None if not provided.
        context          Request-scoped key/value conditions from
                         ``DecisionRequest.context``, or None.

        Returns a ``Decision`` with an explicit ``PolicyOutcome``. Never None.
        Never raises (catch your own exceptions and return a safe outcome).
        """
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
        resource_id: str | None = None,
        identity_context: IdentityContext | None = None,
        context: dict[str, Any] | None = None,
    ) -> Decision:
        """
        Evaluate a subject's request to perform an action on a resource.

        Applies deny-overrides semantics across all registered rules.
        Returns NOT_APPLICABLE if no rule covers the action (which the
        EnforcementPoint resolves to DENY by default).
        """
        # Collect per-rule evaluation records for traceability. Each entry is a
        # (rule_name, outcome_value, reason) tuple using plain strings so the
        # audit package does not need to import PolicyOutcome.
        evaluations: list[tuple[str, str, str]] = []
        first_allow: Decision | None = None

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
                    type(rule).__name__,
                    action,
                    str(subject),
                )
                err_entry = (type(rule).__name__, PolicyOutcome.DENY.value, str(exc))
                evaluations.append(err_entry)
                return Decision(
                    outcome=PolicyOutcome.DENY,
                    reason=f"Rule evaluation error in {type(rule).__name__}: {exc}",
                    evaluated_by=type(rule).__name__,
                    evaluated_rules=evaluations,
                    is_error=True,
                )

            evaluations.append((decision.evaluated_by, decision.outcome.value, decision.reason))

            if decision.outcome == PolicyOutcome.DENY:
                log.debug(
                    "rule=%-28s  subject=%-16s  action=%-32s  resource=%-16s  DENY",
                    decision.evaluated_by,
                    str(subject),
                    action,
                    resource_id or "—",
                )
                # Deny overrides — stop immediately; attach full trace so far.
                return Decision(
                    outcome=PolicyOutcome.DENY,
                    reason=decision.reason,
                    evaluated_by=decision.evaluated_by,
                    evaluated_rules=evaluations,
                )

            if decision.outcome == PolicyOutcome.ALLOW and first_allow is None:
                first_allow = decision

        if first_allow is not None:
            log.debug(
                "rule=%-28s  subject=%-16s  action=%-32s  resource=%-16s  ALLOW",
                first_allow.evaluated_by,
                str(subject),
                action,
                resource_id or "—",
            )
            return Decision(
                outcome=PolicyOutcome.ALLOW,
                reason=first_allow.reason,
                evaluated_by=first_allow.evaluated_by,
                evaluated_rules=evaluations,
            )

        # No rule handled this request — default deny.
        log.warning(
            "PolicyEngine: no rule covered action=%r subject=%s — NOT_APPLICABLE (default deny)",
            action,
            str(subject),
        )
        return Decision(
            outcome=PolicyOutcome.NOT_APPLICABLE,
            reason=(
                f"No policy rule is registered for action '{action}'. "
                "Every action that can be requested must be covered by at least "
                "one rule in the engine's chain. Default: deny."
            ),
            evaluated_by="PolicyEngine",
            evaluated_rules=evaluations,
        )
