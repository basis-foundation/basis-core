# Decision Flow

This document traces the path of an authorization request from field-protocol message to decision record.

## Stages

### 1. Field-protocol message arrives at the adapter

A field device or upstream component sends a message in its native protocol format. The adapter receives it.

Examples: a BACnet WriteProperty request, a Modbus write to a holding register, an MQTT command message.

### 2. Adapter normalizes the message

The adapter extracts the operationally meaningful content and maps it to the authorization model's primitives:
- **resource_id**: the normalized identifier for the targeted resource (e.g., `"hvac:zone-a"`).
- **action**: the action name from the domain vocabulary (e.g., `"write:hvac:setpoint"`).
- **subject_id** (if available): the identity of the requesting subject from the authenticated session.

The adapter constructs a `DecisionRequest` from this normalized representation. Protocol-specific field names, register addresses, object identifiers, and topic strings do not appear in the `DecisionRequest`.

If the adapter cannot determine identity context (for example, for a device-originated telemetry message with no authenticated session), `subject_id` is absent or represents the device's own identifier.

### 3. DecisionRequest is submitted to the EnforcementPoint

The enforcement point receives the `DecisionRequest`. It constructs a `Subject` from the request fields (or uses a pre-constructed `Subject` if the caller provides one from an authenticated session).

### 4. PolicyEngine evaluates the request

The enforcement point calls `PolicyEngine.evaluate(subject, action, resource_id,
identity_context, context)`. The engine applies deny-overrides semantics across
all registered rules:

- Each rule returns an explicit `Decision` with a `PolicyOutcome` of ALLOW, DENY,
  or NOT_APPLICABLE. Rules never return None.
- If any rule returns DENY, the engine returns that DENY decision immediately.
  A single explicit denial overrides any number of grants.
- If any rule returns ALLOW and no rule returned DENY, the engine returns the
  first ALLOW decision.
- If all rules return NOT_APPLICABLE, the engine returns a NOT_APPLICABLE
  decision. The EnforcementPoint resolves this to DENY (default deny).

This means an uncovered action is never silently permitted. Every action
reachable from an adapter must be covered by at least one rule.

### 5. AuditEvent is written

Before returning the response to the caller, the enforcement point writes an `AuditEvent` containing the full context of the decision: subject, resource, action, outcome, policy version, and timestamp. This happens regardless of the outcome — ALLOW and DENY decisions are both recorded.

A failure to write the audit record is itself logged as an error. It does not change the decision outcome.

### 6. DecisionResponse is returned

The `DecisionResponse` carries the outcome (ALLOW, DENY, or NOT_APPLICABLE), the reason, and the evaluated-by field identifying which policy produced the decision.

### 7. Adapter applies the decision

The adapter receives the `DecisionResponse` and applies it:
- ALLOW: the operation proceeds. The adapter sends the command to the target device (or permits the telemetry to flow).
- DENY: the adapter rejects the request. It may return an error to the upstream component.

## What the policy engine does not do

The policy engine does not route, relay, or proxy operational traffic. Commands do not pass through it; authorization requests do. A write command to an HVAC controller travels from the adapter to the controller directly, after the enforcement point has confirmed the action is permitted.

## Control plane vs. data plane

In the decision flow above, all traffic through the `PolicyEngine`, `EnforcementPoint`, and `AuditWriter` is control-plane traffic: it describes what is permitted, not what is happening. Operational commands, sensor readings, and device telemetry are data-plane traffic. They travel through the adapter and the device protocol layer, not through the policy engine.

This separation is what allows enforcement to add latency only to the authorization check, not to every byte of operational data.
