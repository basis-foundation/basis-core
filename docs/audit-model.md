# Audit Model

The audit record is a first-class component of the authorization boundary, not a log appended for compliance purposes. Every authorization decision produces an audit record. The completeness and integrity of the audit trail is a property the system must actively maintain.

## What is recorded

Every `AuditEvent` contains:

- **Who**: subject identifier, name, type, and roles at the time of the event.
- **What**: action name and resource identifier.
- **When**: UTC timestamp of the event (not the write time).
- **Outcome**: ALLOWED, DENIED, or ERROR.
- **Why**: the reason string from the policy Decision, and the name of the policy that produced it.
- **Which policy version**: the policy version string in effect at evaluation time.
- **Correlation**: request_id linking the audit record to the DecisionRequest and DecisionResponse.

## What is not recorded in the library

The library defines the structure and the write interface. It does not define:

- Where records are persisted (database, append-only file, log pipeline).
- How records are protected from modification (append-only storage, cryptographic chaining).
- How long records are retained.
- Who has read access to audit records.

These are deployment concerns that the application must address.

## The AuditWriter protocol

Any object implementing `write(event: AuditEvent) -> None` satisfies the `AuditWriter` protocol. Two implementations are included:

- `NullAuditWriter`: discards all events. Suitable for tests only.
- `LogAuditWriter`: writes structured JSON to a Python logger. Suitable for development and log-aggregation pipelines.

Production deployments need an `AuditWriter` that provides append-only semantics, survives process restarts, and is administratively independent of the systems being audited.

## Immutability

An audit record that can be modified after the fact is not a trustworthy record. The `AuditEvent` type is immutable (Pydantic frozen model). The library cannot enforce immutability at the storage layer — that is the responsibility of the backend. But the library does not provide any mechanism to modify a record after it is written.

## Audit gaps

The library makes a best-effort attempt to write every audit record. If `AuditWriter.write()` raises, the exception is caught, logged as an error, and the calling operation continues. An audit failure does not change the decision outcome.

This means there are conditions under which a decision is made but no audit record is written. Those conditions must be treated as operational incidents and monitored for. The absence of audit records in a time window is an observable condition that monitoring should detect, not a silent gap that goes unnoticed.

## Event types

`AuditEventType` classifies the category of each event:

- `authorization_decision`: the result of a policy engine evaluation.
- `policy_change`: a policy was added, modified, or removed.
- `identity_event`: a credential was issued, revoked, or expired.
- `emergency_override`: an operator invoked a break-glass procedure.
- `adapter_event`: an adapter started, stopped, or encountered an error.
- `system_event`: other security-relevant system activity.

Not all of these types are populated by the library itself. Applications are expected to produce the full range of event types using the same `AuditEvent` structure and the same `AuditWriter` pipeline.
