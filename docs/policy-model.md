# Policy Model

A policy rule is a stateless function that receives a subject, an action, an
optional resource identifier, an optional identity context, and an optional
context map. It returns an explicit outcome: ALLOW, DENY, or NOT_APPLICABLE.

The policy engine collects outcomes from all rules and applies deny-overrides
semantics to produce a single Decision.

## PolicyOutcome

Three values cover the full evaluation space:

**ALLOW** — the rule positively permits the request. The subject holds the
necessary attributes for this rule to grant access.

**DENY** — the rule positively prohibits the request. The subject or resource
does not satisfy the rule's conditions. This is an explicit refusal, not a
default.

**NOT_APPLICABLE** — the rule has no opinion on this request. The request falls
outside the rule's scope (for example, the action is not in this rule's table,
or the resource type is not relevant). The engine continues to the next rule.
NOT_APPLICABLE is not the same as DENY; returning it allows downstream rules
to grant or deny the request.

A rule must use NOT_APPLICABLE — not DENY — for requests outside its scope.
Returning DENY for unknown actions would prevent any other rule from allowing
them.

## Deny-overrides semantics

The engine applies deny-overrides when aggregating outcomes from the full rule
list:

1. If any rule returns DENY, the final decision is DENY. A single explicit
   refusal overrides any number of grants. The engine returns the first DENY
   decision encountered.
2. If any rule returns ALLOW and no rule returned DENY, the final decision is
   ALLOW. The engine returns the first ALLOW decision.
3. If all rules return NOT_APPLICABLE, the final decision is NOT_APPLICABLE.
   The EnforcementPoint resolves this to DENY (default deny).

This differs from chain-of-responsibility ("first match wins"). With
deny-overrides, reordering rules cannot bypass an explicit prohibition.

## Default deny

If no rule covers a request — all rules return NOT_APPLICABLE — the engine
returns NOT_APPLICABLE and the EnforcementPoint applies default deny. An
uncovered action is never silently permitted.

Default deny means: access requires an explicit grant. Omitting an action from
all rule tables is not a way to allow it; it is a way to deny it.

## PolicyRule contract

Any object that implements the `PolicyRule` protocol can be registered in the
engine:

```python
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
```

Rules must be stateless. They must not modify system state, make network
calls, or perform I/O during `evaluate()`. State needed for evaluation (e.g.,
a role table) is loaded at construction time and held as an immutable reference.

## Provided rule types

**RolePolicyRule** maps action names to sets of permitted roles (RBAC). If the
action is in the table and the subject holds a permitted role, the outcome is
ALLOW. If the action is in the table and the subject holds none of the required
roles, the outcome is DENY. If the action is not in the table, the outcome is
NOT_APPLICABLE.

**ResourceTypePolicyRule** constrains which resource types are permitted targets
for an action. If no resource_id is present, the outcome is NOT_APPLICABLE. If
the resource's type prefix is in the permitted set, the outcome is ALLOW. If it
is not, the outcome is DENY. This rule is most useful in combination with
RolePolicyRule to enforce that a role-permitted action can only target specific
resource categories.

**ActionPolicyRule** assigns explicit outcomes to named actions. Use this to
build allowlists (map specific actions to ALLOW) or denylists (map specific
actions to DENY). Actions not present in the map return NOT_APPLICABLE. This
rule is useful for enforcing organization-wide restrictions independent of role.

## Composing rules

Rules compose naturally under deny-overrides. Example: restrict operators to
HVAC resources only.

```python
engine = PolicyEngine(policies=[
    ResourceTypePolicyRule(permitted_types={ResourceType.HVAC}),
    RolePolicyRule({"write:hvac:setpoint": {"operator", "admin"}}),
])
```

For a request targeting `hvac:zone-a` with action `write:hvac:setpoint`:

- `ResourceTypePolicyRule` sees type "hvac" in its permitted set → ALLOW.
- `RolePolicyRule` sees the action in its table and checks the subject's roles.
  If the subject is an operator → ALLOW. If not → DENY.

If `RolePolicyRule` returns DENY, that DENY overrides the ALLOW from
`ResourceTypePolicyRule`. The request is denied.

For a request targeting `device:chiller-1` with the same action:

- `ResourceTypePolicyRule` sees type "device" is not HVAC → DENY.
- The engine returns DENY immediately. The role check is never reached.

## What intentionally does not belong here

**Time-of-day restrictions.** These are not implemented. A `TimeWindowPolicy`
stub existed in an earlier version and has been removed. Time-window logic
belongs in a future rule type with a proper definition of "time context" for
the operational environment.

**ABAC expressions.** No CEL, Rego, OPA, or expression language. Attribute
conditions can be introduced by writing a concrete rule class that inspects the
`context` parameter. The mechanism exists; the DSL does not.

**External lookups.** Rules must not consult databases, services, or files
during evaluation. State is loaded at construction time. This constraint exists
to ensure predictable, auditable, and latency-bounded evaluation.

**Risk scores and obligations.** These introduce dependencies on external
state and execution at evaluation time. Neither belongs in the current model.

The policy model is intentionally small. Adding sophistication before the
operational requirements justify it produces complexity without benefit. When
a requirement cannot be satisfied with the current rule types, the correct
response is to write a new stateless rule class — not to extend the evaluation
contract.

## Policy versioning

The `EnforcementPoint` accepts a `policy_version` string that is included in
every `DecisionResponse` and `AuditEvent`. Policy versions allow audit records
to be correlated with the specific rule configuration in effect at evaluation
time.

Policy versioning is the application's responsibility. This library records the
version the caller provides; it does not manage policy lifecycle, distribution,
or storage.

## Compatibility

Action names used in policy rules are compatibility-sensitive contracts. An action name that appears in a deployed policy must continue to evaluate correctly for the lifetime of that policy. Renaming or narrowing the scope of an established action name is a breaking change — it produces silent denials in policies that reference the prior name without any runtime error.

Policy evaluation semantics must be stable across kernel version increments. Adding a new policy construct is additive. Changing the evaluation behavior of an existing construct — including the default-deny outcome for unmatched actions — is a breaking change.

See `docs/evaluation-semantics.md` for the precise behavioral specification of the engine — including short-circuit rules, evaluated_rules contents, and a full breaking-change catalogue. See `docs/architecture/compatibility-philosophy.md` in basis-architecture for the compatibility commitments that govern these decisions.
