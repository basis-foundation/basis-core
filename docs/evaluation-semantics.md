# Evaluation Semantics

This document specifies the deterministic evaluation contract of the `PolicyEngine`. The behaviors described here are kernel contracts. Changing any of them is a breaking change to the authorization boundary.

Cross-references: `docs/policy-model.md` describes the rule types and deny-overrides rationale. `docs/decision-flow.md` covers the full request-to-audit path. `docs/failure-modes.md` describes fail-closed guarantees. `docs/enforcement-boundary.md` covers the EnforcementPoint guarantees that depend on these semantics. `docs/architecture/compatibility-philosophy.md` in basis-architecture establishes why evaluation semantics must be stable.

---

## What this document specifies

`PolicyEngine.evaluate()` takes a subject, action, resource identifier, and optional context, walks a list of registered `PolicyRule` implementations in registration order, and returns a single `Decision`. This document specifies exactly what that means: how outcomes are combined, what short-circuits, what does not, what appears in the per-rule trace, how failures are handled, and what the returned `Decision` contains.

These are not implementation notes. They are the behavioral contract that enforcement points, audit consumers, and policy authors can rely on.

---

## Outcome values

Three values cover the full evaluation space at both the rule and engine level.

**ALLOW** — a rule positively permits the request. The subject holds the necessary attributes for this rule to grant access. At the engine level, ALLOW means the request is permitted, subject to the denial check.

**DENY** — a rule positively prohibits the request. This is an explicit, reasoned refusal, not a fallback. At the engine level, a single DENY from any rule is the final outcome regardless of other rules' outcomes. Reordering rules cannot cause a DENY to be skipped.

**NOT_APPLICABLE** — the rule has no opinion on this request. The request falls outside the rule's scope (for example, the action is not in this rule's table, or the resource type is not relevant). NOT_APPLICABLE is not equivalent to DENY. A rule that returns NOT_APPLICABLE is saying "I don't know; ask the next rule." A rule must use NOT_APPLICABLE — not DENY — for requests outside its scope. Returning DENY for unknown actions would prevent downstream rules from allowing them.

At the engine level, if all rules return NOT_APPLICABLE, the engine returns NOT_APPLICABLE. The `EnforcementPoint` resolves NOT_APPLICABLE to DENY (default deny). NOT_APPLICABLE is preserved in the `DecisionResponse` so callers can distinguish between an explicit denial and an uncovered action. Both map to `AuditOutcome.DENIED` in the audit record.

---

## The evaluation algorithm

The engine evaluates rules in the order they were registered at construction. The algorithm is as follows:

1. Initialize an empty `evaluations` list and a `first_allow` placeholder.
2. For each rule in registration order:
   a. Call `rule.evaluate(subject, action, resource_id, identity_context, context)`.
   b. Append `(rule_name, outcome_value, reason)` to `evaluations`.
   c. If the outcome is **DENY**: return `Decision(DENY, ...)` immediately with `evaluated_rules=evaluations`. No further rules are called.
   d. If the outcome is **ALLOW** and `first_allow` is not yet set: record this rule as `first_allow`. Continue to the next rule.
   e. If the outcome is **NOT_APPLICABLE**: continue to the next rule.
3. After all rules have been evaluated:
   - If `first_allow` is set: return `Decision(ALLOW, ...)` using `first_allow.reason` and `first_allow.evaluated_by`, with `evaluated_rules=evaluations` (which covers all rules).
   - If no rule returned ALLOW or DENY: return `Decision(NOT_APPLICABLE, ...)` with `evaluated_by="PolicyEngine"` and `evaluated_rules=evaluations`.

This algorithm has two critical asymmetries that must be understood by policy authors and test writers alike.

---

## DENY short-circuits; ALLOW does not

**DENY short-circuits.** When a rule returns DENY, the engine returns immediately. Rules registered after the denying rule are never called for this evaluation. The `evaluated_rules` list in the returned `Decision` contains only the rules evaluated up to and including the denying rule, not the full registration list.

**ALLOW does not short-circuit.** When a rule returns ALLOW, the engine records it as `first_allow` and continues to the next rule. Every registered rule is called. The reason for this asymmetry is that deny-overrides semantics guarantee that a prohibition cannot be bypassed by reordering rules. If ALLOW short-circuited, a DENY from a later rule would be skipped for any request covered by an earlier ALLOW, making rule order security-critical. Under deny-overrides, it is not.

**Consequence for multi-rule configurations:** In a two-rule configuration `[AllowRule, DenyRule]`, both rules are always evaluated. AllowRule returns ALLOW (recorded as `first_allow`), then DenyRule is called. If DenyRule returns DENY, that DENY is returned immediately and overrides the ALLOW. If DenyRule returns NOT_APPLICABLE, AllowRule's ALLOW is returned. If DenyRule returns ALLOW, AllowRule's ALLOW is still returned (first ALLOW wins for `evaluated_by` and `reason`, but both evaluations appear in `evaluated_rules`).

**Consequence for the `short_circuited` flag:** The `DecisionTrace.short_circuited` flag in the audit record is `True` when the outcome is DENY and the number of evaluated rules is fewer than the total number of rules registered in the engine. It is `False` in all other cases, including NOT_APPLICABLE outcomes where no rules matched.

---

## First ALLOW wins

When multiple rules return ALLOW, the engine uses the outcome, reason, and `evaluated_by` from the **first** rule (in registration order) that returned ALLOW. All rules are still evaluated. The `evaluated_rules` list contains all of them. The `first_allow` rule is not privileged in any other way; later ALLOWs appear in the trace with equal status.

This means the rule that "gets credit" in `evaluated_by` (and therefore in the `DecisionResponse.evaluated_by` field and the audit record) is a function of registration order. Policy authors who need a specific rule to be authoritative for a given action should ensure it is registered first in the list.

---

## Empty policy list and uncovered actions

An engine with no registered rules evaluates every request and returns NOT_APPLICABLE. The `EnforcementPoint` resolves this to DENY. An action that falls outside the scope of all registered rules produces the same result.

Default deny means: access requires an explicit grant. Omitting an action from all rule tables is not a way to allow it. It is a way to deny it.

---

## Rule exceptions: fail-closed with partial trace

If a rule raises an unhandled exception during `evaluate()`:

1. The engine logs the exception.
2. The exception entry is appended to `evaluations` as `(rule_name, "deny", str(exc))`.
3. The engine returns `Decision(DENY, ..., is_error=True)` immediately with `evaluated_rules=evaluations` containing only the rules evaluated up to and including the failing rule. Rules registered after the failing rule are not called.

The `is_error=True` flag signals the `EnforcementPoint` to: replace the reason with a sanitized message (the raw exception text is never returned to the caller), set `failure_reason=POLICY_ERROR` on the `DecisionResponse`, and write an `AuditEvent` with `outcome=ERROR`.

This is the same short-circuit behavior as DENY, with the addition of the `is_error` flag. A rule error is always fail-closed: the outcome is always DENY, never ALLOW or NOT_APPLICABLE.

---

## evaluated_by

`Decision.evaluated_by` names the rule that produced the decision-determining outcome:

- For DENY: the name of the rule that returned DENY.
- For ALLOW: the name of the first rule that returned ALLOW (in registration order).
- For NOT_APPLICABLE (all rules exhausted): `"PolicyEngine"`.
- For error: the name of the rule that raised the exception.

`evaluated_by` appears verbatim in `DecisionResponse.evaluated_by` and in the `AuditEvent`. It is used for audit correlation, not for policy logic.

---

## evaluated_rules and the per-rule trace

`Decision.evaluated_rules` is an ordered list of `(rule_name, outcome_value, reason)` tuples, where `outcome_value` is a plain string (`"allow"`, `"deny"`, or `"not_applicable"`), not a `PolicyOutcome` enum value.

It contains entries for every rule that was called during this evaluation — no more, no less:

- For DENY outcomes (including errors): entries up to and including the denying rule.
- For ALLOW outcomes: entries for all registered rules (because ALLOW does not short-circuit).
- For NOT_APPLICABLE outcomes: entries for all registered rules.

The `EnforcementPoint` converts `evaluated_rules` into a `DecisionTrace` for the `AuditEvent`. `DecisionTrace.matched_rule_names` returns the subset of rule names whose outcome was ALLOW or DENY; NOT_APPLICABLE entries are excluded.

---

## Audit outcome mapping

The `EnforcementPoint` maps engine outcomes to audit outcomes as follows:

| Engine outcome    | `DecisionResponse.outcome` | `AuditEvent.outcome`  |
|---|---|---|
| ALLOW             | `allow`                    | `allowed`             |
| DENY              | `deny`                     | `denied`              |
| NOT_APPLICABLE    | `not_applicable`           | `denied`              |
| Error (is_error)  | `deny`                     | `error`               |

NOT_APPLICABLE maps to `AuditOutcome.DENIED` in the audit record because the operational effect is denial: the request was not permitted. The distinction between DENY and NOT_APPLICABLE is preserved in `DecisionResponse.outcome` and in `DecisionTrace.final_outcome` for diagnostic purposes.

---

## Statelessness and determinism

The engine holds no mutable state after construction. `evaluate()` does not modify any instance attribute. The policies list is fixed at construction time and never mutated during evaluation.

**Determinism guarantee:** For the same subject, action, resource identifier, and policy configuration, `evaluate()` always returns the same outcome. There is no dependence on wall-clock time, call count, thread identity, or any external state.

This guarantee is a precondition for the audit record being a reliable reflection of what happened. A non-deterministic engine would produce audit records that could not be used to reconstruct the authorization decision.

**Thread safety:** Because the engine is stateless after construction and rule implementations must also be stateless, the same `PolicyEngine` instance is safe to share across concurrent requests, provided the registered rule implementations are also thread-safe. The engine itself introduces no synchronization requirements.

---

## What constitutes a breaking change to evaluation semantics

The following changes to evaluation behavior are breaking changes to the kernel contract. They require a major version increment, an ADR, and a defined migration path.

**Changes to outcome resolution:**
- Changing DENY to not short-circuit (would allow later rules to override a DENY).
- Changing ALLOW to short-circuit (would allow a DENY from a later rule to be skipped).
- Changing which ALLOW is returned when multiple ALLOWs exist (first vs. last).
- Changing NOT_APPLICABLE to permit rather than deny at the `EnforcementPoint`.

**Changes to default behavior:**
- Changing the default-deny outcome for uncovered actions (NOT_APPLICABLE resolved to ALLOW instead of DENY).
- Changing the behavior of an empty policy list (currently: NOT_APPLICABLE → DENY).

**Changes to exception handling:**
- Changing exception handling from fail-closed DENY to anything other than DENY.
- Propagating raw exception text to the caller in the `reason` field.

**Changes to the trace contract:**
- Changing the semantics of `evaluated_rules` (e.g., including rules that were not called).
- Changing the `short_circuited` flag definition.
- Changing `evaluated_by` semantics (e.g., using last ALLOW instead of first).

**Changes to audit outcome mapping:**
- Changing the mapping of NOT_APPLICABLE to AuditOutcome (currently: DENIED).
- Changing the mapping of error outcomes (currently: ERROR).

Adding new optional fields to `Decision`, adding new `PolicyOutcome` values with defined semantics, and adding new rule types are additive changes. They do not break existing policy configurations or audit consumers that handle unknown values gracefully.

See `docs/architecture/compatibility-philosophy.md` in basis-architecture for the governing principles behind these definitions.
