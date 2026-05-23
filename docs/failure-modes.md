# Failure Modes

This document describes the conditions under which the authorization boundary behaves unexpectedly, and what the library does (and does not do) in each case.

## Policy engine: uncovered action

**Condition**: A request is submitted for an action that no policy in the chain handles.

**Library behavior**: The engine returns DENY with `evaluated_by = "PolicyEngine"` and a reason indicating that the action is not covered.

**What this means in practice**: Either the action name is misspelled, or the policy configuration does not cover a case it should. Both are configuration errors. Monitoring should alert on decisions with `evaluated_by = "PolicyEngine"`.

## Policy engine: policy raises an exception

**Condition**: A `Policy.evaluate()` call raises an unexpected exception.

**Library behavior**: The exception is caught. The engine returns DENY and logs the exception. The audit record reflects the denial.

**Note**: Individual policy implementations should also catch exceptions internally if they perform any operation that can fail (e.g., attribute lookups). The engine's catch is a last resort, not a design pattern.

## EnforcementPoint: audit write fails

**Condition**: `AuditWriter.write()` raises an exception.

**Library behavior**: The exception is caught and logged as an error. The
`DecisionResponse` is returned to the caller unchanged. The decision is not
reversed.

**Why the decision stands**: Audit is evidence, not enforcement. The policy
engine has already evaluated the request and produced a decision. That decision
is correct based on the policy and the subject's credentials at that moment.
Reversing it because the audit infrastructure failed would mean denying an
authorized operator access during an infrastructure incident — the opposite of
operational continuity.

**Consequence**: The audit record for this decision is not written. This is an
audit gap — a decision that occurred but left no record. Audit gaps must be
treated as operational incidents: detected by monitoring, investigated, and
resolved.

**What deployments must do**: Monitor for audit write failures. An audit gap is
a signal that the audit pipeline needs attention. Design monitoring to detect the
absence of expected audit records in a time window, not just the presence of
error log lines — log lines may also be lost if the logging pipeline is the
failure point.

## EnforcementPoint: evaluation raises an exception

**Condition**: An unexpected exception occurs during `PolicyEngine.evaluate()` that is not caught by the engine itself.

**Library behavior**: The exception is caught by the `EnforcementPoint`. A DENY decision is returned. The exception is logged and included in the audit record's reason field.

**What this means**: The caller is told the action was denied. The audit record reflects an error outcome. The caller should treat this as a denial and not retry immediately.

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

**Library behavior**: `RolePolicy` evaluates normally. For any action that requires a role, the result is DENY with a reason indicating the subject holds no applicable roles.

**What this means**: An unauthenticated or minimally authenticated principal receives the access the policy specifies for their actual role set — which, if empty, means no access to any action that requires a role. This is the correct behavior.

## Resource not recognized

**Condition**: A `DecisionRequest` contains a `resource_id` that does not correspond to any registered resource.

**Library behavior**: The library does not maintain a resource registry. The `resource_id` field is treated as an opaque string by the policy engine. The decision is based on the action and subject alone unless the policy explicitly conditions on the resource identifier.

**What this means**: A `RolePolicy` that maps actions to roles will allow or deny based on the subject's roles regardless of whether the resource identifier is valid. A policy that conditions on specific resource identifiers will return None for an unrecognized resource, passing to the next policy. The application must register resource validation logic (in a policy or in the adapter layer) if it needs to reject requests for unknown resources.
