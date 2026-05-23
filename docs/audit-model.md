# Audit Model

An audit record is evidence, not enforcement. Its purpose is to create an
accurate, durable, and independently verifiable account of what happened at
the authorization boundary. It does not control what is permitted — that is
the policy engine's job. An audit failure does not and must not reverse an
authorization decision.

## What is recorded

Every `AuditEvent` for an authorization decision contains:

**Identification** — `event_id` (unique record identifier), `schema_version`
(AuditEvent schema revision), `timestamp` (UTC time the event occurred, not
the time it was written).

**Correlation** — `request_id` (links to the DecisionRequest and
DecisionResponse), `decision_id` (identifier for the decision itself; defaults
to `request_id` when not separately assigned), `correlation_id` (optional
caller-provided trace ID for cross-system correlation, e.g., an HTTP request
ID or a distributed trace ID).

**Subject context** — `subject_id`, `subject_name`, `subject_type`, and the
`subject_roles` held at the time of the request. This is a snapshot: roles
recorded here reflect what the subject held when the decision was made, not
what the subject holds now.

**Resource and action** — `action` name and `resource_id`, exactly as they
appeared in the DecisionRequest.

**Decision** — `outcome` (ALLOWED, DENIED, or ERROR), `reason` (the human-
readable explanation from the winning rule), `evaluated_by` (the name of the
rule that produced the final decision), `policy_version` (the version string
in effect at evaluation time), `matched_rules` (names of rules that returned
ALLOW or DENY — rules that returned NOT_APPLICABLE are excluded).

**Traceability** — `trace` (per-rule evaluation history, when available).
See the section on DecisionTrace below.

## What is not recorded in the library

The library defines the structure and the write interface. It does not define:

- Where records are persisted (database, append-only file, log pipeline).
- How records are protected from modification.
- How long records are retained.
- Who has read access to audit records.

These are deployment concerns. The library's responsibility ends at the
`AuditWriter.write()` call.

## Audit is evidence, not enforcement

The audit system records decisions — it does not make them or constrain them.
Removing an audit record does not undo an authorization decision. Failing to
write an audit record does not prevent an authorized action from proceeding.

This means audit gaps are possible. They must be treated as operational
incidents: detected by monitoring, investigated, and resolved. An audit
infrastructure failure that goes undetected is worse than one that generates
an alert.

## Append-only semantics

Audit records are written once and never modified. The `AuditEvent` model is
immutable (Pydantic frozen model). The library provides no mechanism to update
or delete a record after it is written.

The storage backend must enforce this. An append-only store is the expected
deployment pattern — not because the library enforces it, but because a record
that can be modified after the fact is not a trustworthy record. The library's
contribution is to never provide a write-after-creation interface.

## DecisionTrace

When the `PolicyEngine` evaluates a request, it collects a per-rule evaluation
record as it walks the rule list. The `EnforcementPoint` converts this into a
`DecisionTrace` and embeds it in the `AuditEvent`.

A `DecisionTrace` contains:

- `final_outcome` — the aggregated outcome: "allow", "deny", or "not_applicable".
- `evaluated_rules` — ordered list of `RuleEvaluation` entries, one per rule
  evaluated, each with `rule_name`, `outcome`, and `reason`.
- `short_circuited` — True if evaluation stopped because a DENY was found.
  Remaining rules were not evaluated when this is True.

The trace answers "which rules ran and what did each say?" without requiring
access to the policy engine's internal state after the fact. An auditor can
read the trace and understand exactly why the decision was produced.

`matched_rules` on the `AuditEvent` is derived from the trace: it contains
only the names of rules that returned "allow" or "deny". Rules that returned
"not_applicable" are excluded — they had no opinion on the request.

Traces are optional. `AuditEvent` records are valid and complete without one.
When a rule is written that does not produce trace data (e.g., a third-party
rule implementation), the `trace` field is null.

## The AuditWriter protocol

Any object implementing `write(event: AuditEvent) -> None` satisfies the
`AuditWriter` protocol. Two implementations are included:

- `NullAuditWriter` — discards all events. Suitable for unit tests only.
- `LogAuditWriter` — writes structured JSON to a Python logger. Suitable for
  development and log-aggregation pipelines.

Production deployments need an `AuditWriter` that provides append-only
semantics, survives process restarts, and is administratively independent of
the systems being audited.

## Normalized context, not raw protocol payloads

AuditEvent fields contain normalized, protocol-neutral values. They do not
contain BACnet object identifiers, Modbus register addresses, MQTT topic
strings, or HTTP headers. Those raw protocol values belong in the adapter
layer. By the time a record reaches the `AuditWriter`, the subject, resource,
and action have already been expressed in the domain vocabulary.

This means audit records can be read and queried without knowledge of the
underlying field protocol. A compliance auditor does not need to understand
BACnet to read an HVAC setpoint authorization record.

## Audit gaps

If `AuditWriter.write()` raises, the exception is caught and logged. The
`DecisionResponse` is returned unchanged. The decision is not reversed.

The conditions under which a gap occurs must be monitored. The absence of
audit records in a time window is observable and must be treated as a signal
that the audit pipeline needs attention. Silent gaps are operationally worse
than visible failures.

## Event types

`AuditEventType` classifies the category of each event:

- `authorization_decision` — the result of a policy engine evaluation.
- `policy_change` — a policy was added, modified, or removed.
- `identity_event` — a credential was issued, revoked, or expired.
- `emergency_override` — an operator invoked a break-glass procedure.
- `adapter_event` — an adapter started, stopped, or encountered an error.
- `system_event` — other security-relevant system activity.

## Schema versioning

`AuditEvent.schema_version` identifies the schema revision in effect when the
record was written. The current value is `"1.1"`. Consumers should read this
field to determine which optional fields are present. Fields are added, never
removed or renamed, once a schema version is deployed.
