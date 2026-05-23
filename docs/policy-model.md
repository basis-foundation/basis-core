# Policy Model

A policy is a component that, given a subject, an action, and an optional resource identifier, returns either a Decision or None. Returning None means "I do not cover this case; pass to the next policy." Returning a Decision (ALLOW or DENY) stops evaluation.

## Chain of responsibility

The `PolicyEngine` walks a list of `Policy` implementations in order. The first policy to return a non-None Decision wins. If no policy claims the action, the engine returns DENY. This fail-closed default is deliberate.

The order of policies in the chain determines precedence. Policies with higher precedence are placed first. A common ordering:

1. EmergencyOverridePolicy — defined override conditions (break-glass)
2. RevocationPolicy — check for recently revoked credentials
3. ZoneScopePolicy — zone-based role grants
4. TimeWindowPolicy — time-of-day or window restrictions
5. RolePolicy — base RBAC role mapping

This ordering is not enforced by the library. It is a deployment configuration decision.

## RolePolicy

`RolePolicy` is the concrete policy included in this library. It maps action names to sets of permitted roles:

```python
ROLE_TABLE = {
    "write:hvac:setpoint":    {"operator", "admin"},
    "read:audit:log":         {"admin"},
    "read:sensor:telemetry":  {"viewer", "operator", "admin"},
}
```

If an action is in the table and the subject holds a permitted role, the result is ALLOW. If the action is in the table and the subject holds none of the permitted roles, the result is DENY. If the action is not in the table, the result is None (pass through).

## Custom policies

Any object that implements `evaluate(subject, action, resource_id) -> Decision | None` satisfies the `Policy` protocol. Custom policies are injected into the engine at construction:

```python
engine = PolicyEngine(policies=[
    MyTimeWindowPolicy(),
    RolePolicy(ROLE_TABLE),
])
```

## Policy evaluation guarantees

**Deterministic.** Given the same inputs and the same policy chain, the engine always returns the same Decision. The engine has no mutable state.

**Fail closed.** An unrecognized action returns DENY. A policy that raises an exception causes the engine's error handling to return DENY and log the failure.

**Auditable.** Every Decision carries the name of the policy that produced it in the `evaluated_by` field. This field appears in audit records.

## Policy versioning

The `EnforcementPoint` accepts a `policy_version` string that is included in every `DecisionResponse` and `AuditEvent` it produces. Policy versions allow audit records to be correlated with the specific policy configuration that was in effect at evaluation time.

Policy versioning is the responsibility of the application. This library does not manage policy lifecycle, distribution, or versioning — it records what version the caller provides.

## What does not belong in a policy

**Protocol-specific logic.** A policy must not inspect Modbus register addresses, BACnet object identifiers, or MQTT topic strings. If a policy needs to distinguish resources served by different protocols, it does so using the normalized resource identifier and type — which the adapter has already set.

**Infrastructure calls.** A policy must not make database queries, network requests, or file I/O during evaluation. Policy implementations that need external state should load that state at construction time and hold it as an in-memory reference.

**Side effects.** A policy implementation must not modify system state. It evaluates and returns a Decision. Any operation that has consequences (writing a log, sending a notification) belongs in the audit path or in the application, not in the policy chain.
