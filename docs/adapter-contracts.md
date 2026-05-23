# Adapter Contracts

Adapters are the boundary between field-protocol representations and the basis-core domain model. They normalize; the core evaluates.

## What an adapter must do

1. **Implement AdapterBase.** Provide `adapter_id`, `protocol`, `start()`, and `stop()`. The application calls these lifecycle methods; it does not call any protocol-specific method on the adapter.

2. **Normalize before submitting.** Before calling the `EnforcementPoint`, construct a `DecisionRequest` from the normalized representation. The `DecisionRequest` must contain:
   - A normalized `resource_id` in the `"{type}:{qualifier}"` format.
   - An `action` name from the `basis_core.domain.action` vocabulary.
   - A `subject_id` derived from the authenticated session, if one is available.

3. **Apply the Decision.** After receiving a `DecisionResponse`, permit the operation (ALLOW) or reject it (DENY). Do not apply your own authorization logic in addition to the policy decision.

4. **Not contain authorization logic.** An adapter must not evaluate whether an action is permitted. That is the policy engine's job. An adapter that checks roles, inspects tokens for specific claims, or applies its own allow/deny rules introduces a second authorization path that is unaudited and inconsistent with the policy configuration.

## What an adapter must not do

- **Import from `basis_core.api`.** Adapters depend on the library; they do not import from the HTTP layer.
- **Expose protocol-specific fields in `DecisionRequest`.** A BACnet object identifier must not appear as a field in a DecisionRequest. It belongs in `NormalizedEvent.payload` as context, not as a field the policy engine reasons about.
- **Make authorization decisions based on protocol membership.** An adapter for BACnet must not assume that any message arriving on the BACnet interface is from a trusted source.
- **Modify the Subject.** The Subject constructed from verified credentials must be passed to the EnforcementPoint unchanged.

## Normalization accuracy

The policy engine trusts the adapter's normalization unconditionally. The engine has no protocol knowledge with which to verify that a `resource_id` of `"hvac:zone-a"` accurately represents the targeted BACnet object or Modbus register. If the adapter maps the wrong resource identifier, the engine will evaluate the wrong question and produce a decision that does not reflect what was actually requested.

Adapter normalization accuracy is a correctness requirement with security consequences. Adapter implementations must be tested against the full object model and register map of the devices they serve. Changes to device configuration that affect the semantic content of protocol messages must trigger a review of the adapter's normalization logic.

## Semantic stability

Normalized resource identifiers and action names appear in audit records. If an adapter changes its normalization (for example, mapping a resource to a different `resource_id`), historical audit records will no longer use the same identifiers as current records. This is a breaking change to the audit trail from an analysis perspective.

Changes to normalization should be treated like action name changes: document them, version them, and account for the discontinuity in audit analysis tools.

## Telemetry vs. commands

Adapters typically handle two directions of traffic:

- **Commands (inbound to the field device)**: These originate from an authenticated session. The adapter normalizes the command, submits a `DecisionRequest`, and applies the decision before forwarding the command.
- **Telemetry (outbound from the field device)**: These originate from devices that cannot authenticate themselves. The adapter normalizes the telemetry and routes it to the telemetry pipeline. No `DecisionRequest` is submitted for device-originated telemetry (unless there is a policy requirement to gate telemetry consumers).

These two directions have different authorization profiles. The audit records they produce have different evidential weight: command records carry verified subject identity; telemetry records carry path metadata. Treat them accordingly in audit analysis.
