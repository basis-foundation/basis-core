"""
basis_core.policy.rules — concrete PolicyRule implementations.

Three rule types are provided. They compose under deny-overrides semantics
in the PolicyEngine. Each returns an explicit PolicyOutcome — never a bare
boolean and never None. NOT_APPLICABLE means "this rule has no opinion;
continue to the next rule."

RolePolicyRule
──────────────
Maps action names to sets of permitted roles (RBAC). The role table is a
plain dict:

    ROLE_TABLE: dict[str, set[str]] = {
        "write:hvac:setpoint": {"operator", "admin"},
        "read:audit:log":      {"admin"},
        ...
    }

  - Action in table, subject holds a permitted role  → ALLOW
  - Action in table, subject holds no permitted role → DENY
  - Action not in table                              → NOT_APPLICABLE

ResourceTypePolicyRule
──────────────────────
Constrains which resource types are permitted. Useful for ensuring that
an action can only target resources of the expected type.

  - resource_id is None                              → NOT_APPLICABLE
  - Resource type is in the permitted set            → ALLOW
  - Resource type is not in the permitted set        → DENY

ActionPolicyRule
────────────────
Assigns explicit outcomes to specific actions. Use to build allowlists
(ALLOW certain actions) or denylists (DENY certain actions).

  - Action is in the action_outcomes map             → that outcome
  - Action is not in the map                        → NOT_APPLICABLE

Composing rules
───────────────
Rules compose under deny-overrides. Example: restrict operator to
HVAC resources only, using role + resource-type constraints:

    engine = PolicyEngine(policies=[
        ResourceTypePolicyRule(permitted_types={ResourceType.HVAC}),
        RolePolicyRule({"write:hvac:setpoint": {"operator", "admin"}}),
    ])

With an HVAC resource: ResourceTypePolicyRule → ALLOW; RolePolicyRule may
ALLOW or DENY based on role. If RolePolicyRule DENYs, that DENY wins.

With a non-HVAC resource: ResourceTypePolicyRule → DENY, which overrides
any ALLOW from RolePolicyRule. The request is denied regardless of role.
"""

from __future__ import annotations

from typing import Any

from basis_core.domain.identity import IdentityContext
from basis_core.domain.resource import ResourceType
from basis_core.domain.subject import Subject
from basis_core.policy.engine import Decision, PolicyOutcome


class RolePolicyRule:
    """
    RBAC policy rule: maps action names to sets of permitted roles.

    Parameters
    ──────────
    role_table   dict[action, set[role_name]]
                 Actions present in the table are handled by this rule.
                 Actions absent from the table return NOT_APPLICABLE.
    rule_name    Label for audit records. Defaults to "RolePolicyRule".
    """

    def __init__(
        self,
        role_table: dict[str, set[str]],
        rule_name: str = "RolePolicyRule",
    ) -> None:
        self._table = {action: frozenset(roles) for action, roles in role_table.items()}
        self._name = rule_name

    def evaluate(
        self,
        subject: Subject,
        action: str,
        resource_id: str | None = None,
        identity_context: IdentityContext | None = None,
        context: dict[str, Any] | None = None,
    ) -> Decision:
        """Evaluate role membership for a known action; NOT_APPLICABLE for unknowns."""
        if action not in self._table:
            return Decision(
                outcome=PolicyOutcome.NOT_APPLICABLE,
                reason=f"Action '{action}' is not in this rule's role table.",
                evaluated_by=self._name,
            )

        permitted_roles = self._table[action]
        if subject.has_role(*permitted_roles):
            return Decision(
                outcome=PolicyOutcome.ALLOW,
                reason=f"Subject holds a role permitted for '{action}'.",
                evaluated_by=self._name,
            )

        return Decision(
            outcome=PolicyOutcome.DENY,
            reason=(
                f"Action '{action}' requires one of {sorted(permitted_roles)}; "
                f"subject holds {sorted(subject.roles) or ['(none)']}."
            ),
            evaluated_by=self._name,
        )


class ResourceTypePolicyRule:
    """
    Constrains which resource types are permitted targets for an action.

    Use this to ensure that actions targeting unexpected resource types are
    rejected at the rule level, independent of role checks.

    Parameters
    ──────────
    permitted_types  Set of ResourceType values that are allowed.
    rule_name        Label for audit records. Defaults to "ResourceTypePolicyRule".

    Outcomes
    ────────
    - resource_id is None                         → NOT_APPLICABLE (no resource
                                                    to check; rule has no opinion)
    - Resource type prefix is in permitted_types  → ALLOW
    - Resource type prefix is not in permitted    → DENY

    The resource type is determined from the type prefix of the resource_id
    string (e.g., "hvac" from "hvac:zone-a"). This does not require
    constructing a full Resource object.
    """

    def __init__(
        self,
        permitted_types: set[ResourceType],
        rule_name: str = "ResourceTypePolicyRule",
    ) -> None:
        self._permitted = frozenset(t.value for t in permitted_types)
        self._name = rule_name

    def evaluate(
        self,
        subject: Subject,
        action: str,
        resource_id: str | None = None,
        identity_context: IdentityContext | None = None,
        context: dict[str, Any] | None = None,
    ) -> Decision:
        if resource_id is None:
            return Decision(
                outcome=PolicyOutcome.NOT_APPLICABLE,
                reason="No resource_id present; resource type check does not apply.",
                evaluated_by=self._name,
            )

        type_prefix = resource_id.split(":")[0] if ":" in resource_id else resource_id

        if type_prefix in self._permitted:
            return Decision(
                outcome=PolicyOutcome.ALLOW,
                reason=f"Resource type '{type_prefix}' is in the permitted set.",
                evaluated_by=self._name,
            )

        return Decision(
            outcome=PolicyOutcome.DENY,
            reason=(
                f"Resource type '{type_prefix}' is not permitted. "
                f"Permitted types: {sorted(self._permitted)}."
            ),
            evaluated_by=self._name,
        )


class ActionPolicyRule:
    """
    Assigns explicit outcomes to named actions.

    Use to build allowlists (map actions to ALLOW) or denylists (map actions
    to DENY). Actions not present in the map return NOT_APPLICABLE.

    Parameters
    ──────────
    action_outcomes  dict[action_name, PolicyOutcome]
                     Explicit outcome for each action this rule governs.
    rule_name        Label for audit records. Defaults to "ActionPolicyRule".

    Example — allowlist:
        ActionPolicyRule({
            "read:sensor:telemetry": PolicyOutcome.ALLOW,
            "read:hvac:state":       PolicyOutcome.ALLOW,
        })

    Example — denylist:
        ActionPolicyRule({
            "write:policy":   PolicyOutcome.DENY,
            "read:audit:log": PolicyOutcome.DENY,
        })
    """

    def __init__(
        self,
        action_outcomes: dict[str, PolicyOutcome],
        rule_name: str = "ActionPolicyRule",
    ) -> None:
        self._outcomes = dict(action_outcomes)
        self._name = rule_name

    def evaluate(
        self,
        subject: Subject,
        action: str,
        resource_id: str | None = None,
        identity_context: IdentityContext | None = None,
        context: dict[str, Any] | None = None,
    ) -> Decision:
        if action not in self._outcomes:
            return Decision(
                outcome=PolicyOutcome.NOT_APPLICABLE,
                reason=f"Action '{action}' is not registered in this rule.",
                evaluated_by=self._name,
            )

        outcome = self._outcomes[action]

        if outcome == PolicyOutcome.ALLOW:
            reason = f"Action '{action}' is explicitly permitted by this rule."
        elif outcome == PolicyOutcome.DENY:
            reason = f"Action '{action}' is explicitly denied by this rule."
        else:
            reason = f"Action '{action}' maps to outcome '{outcome.value}' in this rule."

        return Decision(outcome=outcome, reason=reason, evaluated_by=self._name)
