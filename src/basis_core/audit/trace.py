"""
basis_core.audit.trace — decision traceability structures.

A DecisionTrace captures the per-rule evaluation history that led to a final
authorization decision. It answers the question "why did this decision happen?"
without requiring access to the policy engine's internal state after the fact.

Traces are included in AuditEvent records when the policy engine reports which
rules it evaluated. They are optional — AuditEvents are valid without a trace —
but their presence makes authorization decisions self-explaining.

Design constraints
──────────────────
- Traces are immutable once created. They reflect evaluation state at decision
  time; they cannot be amended.
- Outcome values are plain strings ("allow", "deny", "not_applicable") to avoid
  importing from the policy package. The policy engine and the audit package are
  at the same dependency layer; neither imports from the other.
- Traces capture the rules that were actually evaluated, in order. If the engine
  short-circuited after a DENY, remaining rules are not listed.

Reading a trace
───────────────
The evaluated_rules list is ordered: first rule evaluated is first in the list.
For deny-overrides evaluation:

  - If short_circuited is True, evaluation stopped because a DENY was found.
    The last entry in evaluated_rules is the rule that caused the stop.
  - If short_circuited is False, all registered rules were evaluated.
    The final_outcome reflects the aggregated result.

matched_rules on AuditEvent
─────────────────────────────
AuditEvent.matched_rules is derived from the trace: it contains only the names
of rules that returned "allow" or "deny" (not "not_applicable"). This is the
set of rules that had an opinion on the request.
"""

from __future__ import annotations

from pydantic import BaseModel


class RuleEvaluation(BaseModel):
    """
    The outcome produced by a single policy rule during evaluation.

    Fields
    ──────
    rule_name  Name of the rule (evaluated_by value from Decision).
    outcome    String outcome: "allow", "deny", or "not_applicable".
    reason     Human-readable explanation from the rule's Decision.
    """

    rule_name: str
    outcome: str  # "allow" | "deny" | "not_applicable"
    reason: str

    model_config = {"frozen": True}


class DecisionTrace(BaseModel):
    """
    Complete record of the per-rule evaluations that produced a final decision.

    Fields
    ──────
    final_outcome    The aggregated outcome: "allow", "deny", or "not_applicable".
                     "not_applicable" means no rule had an opinion (default deny
                     is applied by the EnforcementPoint).
    evaluated_rules  Rules evaluated, in order, up to and including the rule that
                     determined the outcome (for deny-overrides: the first DENY).
    short_circuited  True if the engine stopped early because a DENY was found.
                     Remaining rules were not evaluated.
    """

    final_outcome: str  # "allow" | "deny" | "not_applicable"
    evaluated_rules: list[RuleEvaluation] = []
    short_circuited: bool = False

    model_config = {"frozen": True}

    @property
    def matched_rule_names(self) -> list[str]:
        """Names of rules that returned allow or deny (not not_applicable)."""
        return [r.rule_name for r in self.evaluated_rules if r.outcome != "not_applicable"]
