"""
basis_core.policy.rules — concrete Policy implementations.

RolePolicy
──────────
Evaluates authorization by checking whether the subject holds one of the roles
mapped to the requested action. The role table is a plain dict:

    ROLE_TABLE: dict[str, set[str]] = {
        "write:hvac:setpoint": {"operator", "admin"},
        "read:audit:log":      {"admin"},
        ...
    }

If the action is in the table and the subject holds a permitted role → ALLOW.
If the action is in the table and the subject holds no permitted role → DENY.
If the action is not in the table → None (pass to the next policy).

This distinction is important: returning None for unknown actions allows
downstream policies to handle them. Returning DENY for unknown actions would
prevent any downstream policy from allowing them.

Extending the policy model
──────────────────────────
This module is a starting point. Production deployments will need policies that
incorporate contextual attributes. Placeholder stubs are included below for
the most common extension patterns:

  AttributePolicy   Evaluates subject or resource attributes (ABAC).
  TimeWindowPolicy  Restricts actions to defined time windows.
  ZoneScopePolicy   Grants or restricts access based on resource zone.

These stubs define the interface. Implementations are not provided here.
"""

from __future__ import annotations

from typing import Optional

from basis_core.domain.subject import Subject
from basis_core.policy.engine import Decision, Policy


class RolePolicy:
    """
    RBAC-style policy: maps action names to sets of permitted roles.

    Parameters
    ──────────
    role_table   dict[action, set[role_name]]
                 Actions present in the table are handled by this policy.
                 Actions absent from the table pass through (return None).
    policy_name  Label for audit records. Defaults to "RolePolicy".
    """

    def __init__(
        self,
        role_table: dict[str, set[str]],
        policy_name: str = "RolePolicy",
    ) -> None:
        self._table = {action: frozenset(roles) for action, roles in role_table.items()}
        self._name  = policy_name

    def evaluate(
        self,
        subject: Subject,
        action: str,
        resource_id: Optional[str] = None,
    ) -> Optional[Decision]:
        """Evaluate role membership for a known action; pass through unknowns."""
        if action not in self._table:
            return None  # This policy does not cover this action.

        permitted_roles = self._table[action]
        if subject.has_role(*permitted_roles):
            return Decision(
                allowed=True,
                reason=f"Subject holds a role permitted for '{action}'.",
                evaluated_by=self._name,
            )

        return Decision(
            allowed=False,
            reason=(
                f"Action '{action}' requires one of {sorted(permitted_roles)}; "
                f"subject holds {sorted(subject.roles) or ['(none)']}."
            ),
            evaluated_by=self._name,
        )


class AttributePolicy:
    """
    Placeholder for attribute-based policy evaluation (ABAC).

    An AttributePolicy can enforce conditions based on subject attributes
    (e.g., site, clearance level), resource attributes (e.g., zone, criticality),
    or environmental context (e.g., operational mode, maintenance window active).

    Not implemented. Subclass and override evaluate() to provide behavior.
    """

    def evaluate(
        self,
        subject: Subject,
        action: str,
        resource_id: Optional[str] = None,
    ) -> Optional[Decision]:
        """Not implemented. Returns None (pass through) in all cases."""
        return None


class TimeWindowPolicy:
    """
    Placeholder for time-of-day or scheduled-window policy evaluation.

    A TimeWindowPolicy can restrict actions to defined time windows — for
    example, permitting write commands only during a declared maintenance
    window, or restricting operator commands to business hours.

    Not implemented. Subclass and override evaluate() to provide behavior.
    """

    def evaluate(
        self,
        subject: Subject,
        action: str,
        resource_id: Optional[str] = None,
    ) -> Optional[Decision]:
        """Not implemented. Returns None (pass through) in all cases."""
        return None
