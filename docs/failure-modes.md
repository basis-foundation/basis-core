# Failure Modes

This document describes the conditions under which the authorization boundary behaves unexpectedly, and what the library does (and does not do) in each case.

For a comprehensive treatment of the enforcement boundary's guarantees and design rationale, see `docs/enforcement-boundary.md`.

## Malformed request

**Condition**: A request is submitted as a raw dict that fails Pydantic validation, or `Subject` construction fails after a `DecisionRequest` is accepted.

**Library behavior**: The enforcement point returns a DENY with `failure_reason=MALFORMED_REQUEST`. The raw validation error is logged but never returned to the caller. Policy evaluation does not occur.

For raw-dict failures, an audit record is not written because a valid `AuditEvent` requires a validated action field. For subject-construction failures from a valid `DecisionRequest`, an audit record is written with `outcome=ERROR`.

**What this means in practice**: The caller receives a safe denial. The application log records the validation failure with enough context to diagnose the malformed input.

## Policy engine: uncovered action

**Condition**: A request is submitted for an action that no policy rule in the chain handles.

**Library behavior**: The engine returns NOT_APPLICABLE with `evaluated_by="PolicyEngine"`. The enforcement point maps NOT_APPLICABLE to DENY (default deny). The audit record reflects a denied outcome.

**What this means in practice**: Either the action name is misspelled, or the policy configuration does not cover a case it should. Both are configuration errors. Monitoring should alert on decisions with `evaluated_by="PolicyEngine"`.

## Policy engine: rule raises an exception

**Condition**: A `PolicyRule.evaluate()` call raises an unexpected exception.

**Library behavior**: The engine catches the exception, logs it, and returns a DENY `Decision` with `is_error=True`. The enforcement point detects this flag and:
- Replaces the raw exception text with a sanitized denial reason.
- Sets `failure_reason=POLICY_ERROR` on the `DecisionResponse`.
- Writes an `AuditEvent` with `outcome=ERROR` and `failure_reason` in the detail.

The caller receives a DENY with a clean reason string. The raw exception is available only in application logs. See `docs/evaluation-semantics.md` for the precise specification of what appears in `evaluated_rules` and the `is_error` flag when an exception occurs.

**Note**: Individual policy implementations should also catch exceptions internally if they perform any fallible operation. The engine's catch is a last resort, not a design pattern.

## EnforcementPoint: unexpected internal error

**Condition**: An unexpected exception escapes all inner handlers in `EnforcementPoint.evaluate()`.

**Library behavior**: The outer exception handler catches it, logs it, and returns a DENY with `failure_reason=INTERNAL_ERROR`. Raw exception text is not returned to the caller. `evaluate()` never raises.

**What this means**: A `failure_reason=INTERNAL_ERROR` in production logs indicates a bug in basis_core or its immediate dependencies that should be investigated.

## EnforcementPoint: audit write fails

**Condition**: `AuditWriter.write()` raises an exception.

**Library behavior**: The exception is caught and logged as an error. The
`DecisionResponse` already constructed is returned to the caller unchanged. The decision is not reversed.

**Why the decision stands**: Audit is evidence, not enforcement. The policy engine has already evaluated the request and produced a decision. That decision is correct based on the policy and the subject's credentials at that moment. Reversing it because the audit infrastructure failed would mean denying an authorized operator access during an infrastructure incident — the opposite of operational continuity.

**Consequence**: The audit record for this decision is not written. This is an audit gap — a decision that occurred but left no record. Audit gaps must be treated as operational incidents: detected by monitoring, investigated, and resolved.

**What deployments must do**: Monitor for audit write failures. Design monitoring to detect the absence of expected audit records in a time window, not just the presence of error log lines — log lines may also be lost if the logging pipeline is the failure point.

## Policy service unavailable (application-level condition)

**Condition**: The application that hosts the policy engine is unreachable from an enforcement point.

**Library behavior**: The library has no behavior here. The library runs in-process. "Policy service unreachable" is a distributed deployment condition that the application layer must handle.

**What applications must do**: Define and implement a failsafe behavior for this condition before deployment. Options include: fail closed (deny all requests until connectivity is restored), use a local policy cache with a defined staleness limit, or permit a restricted set of operations from a static allowlist. The choice depends on the operational safety requirements of the deployment. Test this behavior under realistic conditions.

## Stale policy cache (application-level condition)

**Condition**: The application is using a local policy cache, and the cache has not been refreshed within its staleness window.

**Library behavior**: The library has no behavior here. Cache management is an application concern.

**What applications must do**: Define the staleness limit. Define what happens when the limit is exceeded (fall back to deny-all, alert an operator, extend the limit with a warning). A stale cache that silently continues enforcing outdated policy is operationally worse than one that alerts and degrades gracefully.

## Subject with no roles

**Condition**: A `DecisionRequest` is submitted with `subject_roles = []`.

**Library behavior**: `RolePolicyRule` evaluates normally. For any action that requires a role, the result is DENY with a reason indicating the subject holds no applicable roles.

**What this means**: An unauthenticated or minimally authenticated principal receives the access the policy specifies for their actual role set — which, if empty, means no access to any action that requires a role. This is the correct behavior.

## Resource not recognized

**Condition**: A `DecisionRequest` contains a `resource_id` that does not correspond to any registered resource.

**Library behavior**: The library does not maintain a resource registry. The `resource_id` field is treated as an opaque string by the policy engine. The decision is based on the action and subject unless the policy explicitly conditions on the resource identifier.

**What this means**: A `RolePolicyRule` that maps actions to roles will allow or deny based on the subject's roles regardless of whether the resource identifier is valid. A policy that conditions on specific resource identifiers will return NOT_APPLICABLE for an unrecognized resource, passing to the next rule. The application must register resource validation logic (in a policy rule or in the adapter layer) if it needs to reject requests for unknown resources.
