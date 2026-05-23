# Enforcement Boundary

The enforcement boundary is the interface between "a request to do something" and "a confirmed authorization decision." It is the point where policy evaluation, identity context, and audit recording converge.

In basis_core, the enforcement boundary is implemented by `EnforcementPoint` in `basis_core.enforcement.enforcement`.

## What the enforcement boundary is

The enforcement boundary receives a `DecisionRequest`, evaluates it against the active policy chain, records the outcome in the audit log, and returns a `DecisionResponse` to the caller.

Nothing enters the system without passing through this boundary. Nothing exits without an audit record being attempted.

## What it guarantees

**Fail closed.** Every failure path returns a DENY. The enforcement point never permits an action it cannot safely evaluate. If the policy engine raises, if a request fails validation, or if an unexpected internal error occurs, the response is DENY with an appropriate `failure_reason` code.

**No raw exception leakage.** Raw exception strings from policy rules, Pydantic validation errors, or internal errors are logged at the appropriate level but are never returned to the caller in the decision reason. Callers receive a fixed, human-readable denial message. The `failure_reason` field identifies the category of failure without exposing internals.

**Always returns.** `EnforcementPoint.evaluate()` never raises. All failure paths are caught and produce a `DecisionResponse`.

**Audit resilience.** A failure to write the audit record does not change the authorization decision. See [Audit failure behavior](#audit-failure-behavior) below.

**Protocol neutrality.** The enforcement point knows nothing about the transport that delivered the request (HTTP, MQTT, WebSocket) or the field protocol the adapter normalized from (BACnet, Modbus, OPC-UA). Those concerns belong to their respective layers.

## What it does not guarantee

**It does not guarantee the audit record was written.** If the audit writer fails, the decision stands but no record is written. This is an audit gap. See [Audit failure behavior](#audit-failure-behavior).

**It does not validate resource existence.** The enforcement point evaluates the action and subject against the policy chain. It does not maintain a resource registry. If a policy needs to condition on resource identity, that logic lives in the policy rule.

**It does not authenticate.** Identity verification happens before the enforcement point is called. The enforcement point receives a verified `Subject` or constructs one from the `DecisionRequest` fields. It assumes the fields reflect a real, authenticated identity.

**It does not cache or batch.** Each call to `evaluate()` is a single, synchronous evaluation. Batching, caching, and asynchronous patterns are concerns for the layer above the enforcement point.

## Fail-closed behavior

The enforcement point is designed to fail closed: when in doubt, deny.

### Malformed request

If a raw dict is passed and fails Pydantic validation, a DENY is returned immediately with `failure_reason=MALFORMED_REQUEST`. The enforcement point does not attempt policy evaluation. An audit record is not written because a valid `AuditEvent` requires a validated action field.

If `Subject` construction fails from an otherwise valid `DecisionRequest` (e.g., a subject_id that passes `DecisionRequest` validation but fails `Subject` construction), a DENY is returned with `failure_reason=MALFORMED_REQUEST` and an audit record is written.

### Policy evaluation error

If a policy rule raises an unhandled exception, the engine catches it, logs it, and returns a DENY `Decision` with `is_error=True`. The enforcement point detects this flag, replaces the reason with a sanitized message, sets `failure_reason=POLICY_ERROR`, and writes an `AuditEvent` with `outcome=ERROR`.

The raw exception text is available in the application logs but is not returned to the caller.

### Unexpected internal error

If an unexpected exception escapes all inner handlers, the outer `except` in `evaluate()` catches it, logs it, and returns a DENY with `failure_reason=INTERNAL_ERROR`. This is the last resort. Its presence in logs indicates a bug that should be investigated.

## Audit failure behavior

The authorization decision is made by the policy engine. Audit is evidence, not enforcement. If `AuditWriter.write()` raises:

- The exception is caught and logged as an error.
- The `DecisionResponse` already constructed is returned unchanged.
- The decision is not reversed.

This means the caller receives the correct authorization outcome even if the audit infrastructure is unavailable. The audit gap — a decision that occurred but left no record — is a separate operational incident.

**What deployments must do:** Monitor for audit write failures. An audit gap must be treated as a security incident, not a normal operational condition. Design monitoring to detect the absence of expected audit records in a time window, not just the presence of error log lines.

## What callers receive

Every `DecisionResponse` includes:

- `outcome` — ALLOW, DENY, or NOT_APPLICABLE (caller treats NOT_APPLICABLE as DENY).
- `reason` — Human-readable explanation. Never contains raw exception text.
- `evaluated_by` — Name of the rule or component that produced the decision.
- `request_id` — Echoed from the request for correlation.
- `policy_version` — Version of the policy set active at evaluation time.
- `failure_reason` — `None` for normal policy decisions. A `FailureReason` enum value for enforcement boundary failures.

Trace information (per-rule evaluation history) is recorded in the `AuditEvent`. It is not returned directly in the `DecisionResponse` to keep the caller interface simple and to avoid exposing policy internals.

## Why transports are intentionally out of scope

The enforcement boundary operates on `DecisionRequest` objects — a normalized, protocol-agnostic representation. The transport that delivered the request (an HTTP handler, an MQTT subscription callback, a BACnet adapter) is responsible for constructing the `DecisionRequest` before calling the enforcement point.

This separation means:

- The policy engine and enforcement point have zero knowledge of transport protocols.
- Transport-layer failures (connection drops, malformed frames, authentication errors) are handled before the enforcement boundary is ever reached.
- The same enforcement point can be shared across all transport adapters in an application.
- Transport adapters can be added, replaced, or removed without touching the policy or enforcement logic.

The boundary between transport and enforcement is documented in `docs/adapter-contracts.md` and `docs/import-boundaries.md`.

## FailureReason codes

| Code | Meaning |
|---|---|
| `malformed_request` | Request did not pass validation. EP never reached policy. |
| `policy_error` | Exception raised during policy rule evaluation. Fail closed. |
| `audit_error` | Reserved. Audit write failed; decision is not affected. |
| `internal_error` | Unexpected exception inside the enforcement point. |

A `failure_reason` of `None` means the decision was produced by normal policy evaluation and no boundary failure occurred.
