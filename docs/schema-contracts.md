# Schema Contracts

The JSON Schemas in `schemas/` are external compatibility contracts, not implementation artifacts. They define the structural and semantic boundaries that all parties relying on basis-core must be able to depend on across time.

This document explains what that commitment means in practice, what kinds of changes are breaking, and what open questions require resolution before certain schemas can be considered fully stabilized.

Cross-references: `docs/architecture/compatibility-philosophy.md` in basis-architecture establishes the overarching rationale. `docs/audit-model.md`, `docs/policy-model.md`, and `docs/adapter-contracts.md` in this repository describe the semantic context behind the schemas. `docs/architecture-references.md` maps these schemas to their governing architecture documents. `docs/schema-versioning.md` defines the schema evolution rules, the breaking-change process, and the open versioning questions.

---

## What these schemas govern

Four schemas define the data structures that cross the authorization kernel boundary:

| Schema | File | Governs |
|---|---|---|
| DecisionRequest | `schemas/decision-request.schema.json` | Normalized authorization requests submitted to the policy engine |
| DecisionResponse | `schemas/decision-response.schema.json` | Authorization decision results returned by the EnforcementPoint |
| AuditEvent | `schemas/audit-event.schema.json` | Structured records of security-relevant events written to the audit pipeline |
| Policy | `schemas/policy.schema.json` | Serialized policy definitions loaded from configuration |

These schemas define the external surface of the kernel. Any component that submits requests, reads decisions, consumes audit records, or distributes policy definitions interacts with this surface. Changes to it are felt by all consumers simultaneously — and, in the case of audit records, retroactively across all stored records.

---

## Stability rules

### Field names are stable once used

A field name that appears in a deployed schema is a stable external identifier. Renaming a field — even with a changelog entry and documented migration — is a breaking change to every consumer that references the old name.

This applies regardless of how minor the rename seems from an implementation perspective. Audit records are retained for compliance and forensic purposes across time ranges that may span years. A renamed field produces a structural discontinuity in the audit record that no amount of documentation fully resolves.

### Removing a required field is a breaking change

Required fields encode invariants that consumers depend on. Removing a required field, or making a required field optional, changes the guarantees the schema provides. This is always a breaking change.

### Adding an optional field is additive

New optional fields (with a defined absence semantics — consumers that receive a record without the new field must not fail) may be added without a major version increment, provided they are accompanied by a schema changelog entry.

All schemas in this repository enforce `additionalProperties: false`. A new field requires an explicit addition to the schema's `properties` object. This is intentional: it makes the schema surface explicit and prevents unintentional extension.

### Changing enum semantics is a breaking change

Removing an enum value, narrowing the set of valid enum values, or redefining the meaning of an existing value are all breaking changes. Adding a new enum value is additive, provided consumers that encounter an unrecognized value can handle it gracefully (forward compatibility).

Relevant enums by schema:

- **DecisionResponse.outcome**: `allow`, `deny`, `not_applicable`
- **DecisionResponse.failure_reason**: `malformed_request`, `policy_error`, `audit_error`, `internal_error`
- **AuditEvent.event_type**: `authorization_decision`, `policy_change`, `identity_event`, `emergency_override`, `adapter_event`, `system_event`
- **AuditEvent.outcome**: `allowed`, `denied`, `error`
- **AuditEvent.subject_type**: `human`, `device`, `service`, `gateway`, `agent`
- **AuditEvent.trace.evaluated_rules[].outcome**: `allow`, `deny`, `not_applicable`
- **Policy.policy_type**: `role_policy`, `resource_type_policy`, `action_policy`, `composite_policy`
- **Policy.evaluation_semantics**: `deny_overrides`
- **Policy.rules[].rule_type**: `role`, `resource_type`, `action`
- **Policy.rules[].permitted_resource_types items**: `hvac`, `sensor`, `zone`, `device`, `gateway`
- **Policy.rules[].action_outcomes values**: `allow`, `deny`, `not_applicable`

### Action and resource identifiers are audit-sensitive

`action` and `resource_id` appear verbatim in both policy rules and audit records. See `docs/architecture/action-vocabulary.md` and `docs/architecture/compatibility-philosophy.md` in basis-architecture for the full stability expectations. In summary:

- An action name used in a deployed policy must evaluate correctly for the lifetime of that policy.
- An action name used in an audit record must be interpretable for the retention period of that record.
- The `resource_id` format pattern (`^[a-z][a-z0-9_-]*(:[a-z0-9][a-z0-9_:/-]*)$`) is a compatibility surface. Changing it invalidates existing resource references in policies and audit records.

### Schema versions must be recorded

`AuditEvent.schema_version` identifies the schema revision in effect when each record was written. Consumers use this field to determine which optional fields are available. Always populate it. The current value is `"1.1"`.

---

## Breaking vs. additive changes — quick reference

| Change | Breaking? |
|---|---|
| Remove a required field | Yes |
| Rename any field | Yes |
| Narrow a field's type | Yes |
| Remove an enum value | Yes |
| Redefine an existing enum value's meaning | Yes |
| Change `additionalProperties` from `false` to `true` | Yes (allows previously-rejected payloads) |
| Add a new required field | Yes (unless backfillable for prior versions) |
| Add a new optional field with defined absence semantics | No — additive |
| Add a new enum value with defined semantics | No — additive |
| Tighten a `pattern` constraint to reject previously-valid values | Yes |
| Loosen a `pattern` constraint to accept previously-rejected values | Depends — review whether it expands the accepted vocabulary |

---

## Canonical examples

The `schemas/examples/` directory contains schema-valid reference examples for each schema. These files do not use the `_comment` annotation convention and are validated by the test suite without modification.

The `examples/` directory contains annotated examples that use `_comment` and similar documentation keys. These are not valid against the schemas as-is because all schemas enforce `additionalProperties: false`. They exist for human readability; use `schemas/examples/` as the machine-readable canonical reference.

---

## Model-to-schema alignment

The Pydantic models in `src/basis_core/` must remain aligned with their corresponding schemas. The test suite in `tests/test_schema_validation.py` verifies this by serializing model instances and validating the output against each schema.

**DecisionRequest.resource_id**: The `DecisionRequest` model enforces the same `{type}:{qualifier}` pattern as the JSON Schema using a `field_validator`. Non-null values are rejected at model construction time if they do not match `^[a-z][a-z0-9_-]*(:[a-z0-9][a-z0-9_:/-]*)$`. `None` is accepted for resource-independent requests. This constraint is intentional: `resource_id` appears verbatim in audit records and must match the resource references in deployed policies. The schema and model are aligned; the schema is authoritative for the format definition.

**AuditEvent.subject_type** *(open compatibility decision)*: The schema restricts `subject_type` to the enum values `human`, `device`, `service`, `gateway`, `agent`, or null. The `AuditEvent` model accepts any string (or null) for this field. This is intentional: the model is designed to be forward-compatible with subject types not yet listed in the schema. A model instance with an unlisted `subject_type` will pass model construction but fail schema validation. Callers should only supply values in the schema enum until the schema is explicitly extended. See the open compatibility questions section.

**Policy schema**: No Pydantic model corresponds to the `policy.schema.json` schema in this repository. The schema describes serialized policy configuration documents, which are loaded and parsed by application code outside the kernel. The schema exists as the canonical specification for that format. Schema-valid fixture examples are in `schemas/examples/policy.json`.

---

## Open compatibility questions

### AuditEvent.subject_type enum vs. model open-string

The `audit-event.schema.json` restricts `subject_type` to the enum `[human, device, service, gateway, agent, null]`. The `AuditEvent` Python model accepts any string to remain forward-compatible with subject types that may be introduced before the schema is updated.

**Open question**: Should the model be tightened to mirror the schema enum, or should the schema be loosened to `type: ["string", "null"]` to match the model's open-string behavior?

The trade-off: schema-side strictness catches invalid subject types in payloads from external producers; model-side openness avoids a breaking model change when new subject types are added. Because `subject_type` is not used by the policy engine for evaluation logic — it is informational context in the audit record — the practical risk of an unlisted value is low. The current open-string model is intentional and should only be changed when the ecosystem's subject type vocabulary is considered stable.

Track this as `OPEN: audit-subject-type-alignment` in the basis-architecture issue tracker.

---

### Schema $id field values

All four schemas use `$id` values of the form `https://basis-core/schemas/{name}.schema.json`. This is not a valid HTTP URL — `basis-core` is not a registered domain name and these URIs are not resolvable. They currently function as opaque namespace identifiers for the purposes of JSON Schema tools.

**Open question**: Should these `$id` values migrate to a stable, resolvable namespace such as `https://schemas.basis-foundation.org/core/v1/{name}.schema.json`?

Implications of migrating:
- Any tooling or code that references the `$id` values directly (e.g., `$ref` pointers from external schemas) would need to be updated.
- Schema `$id` migration is the kind of change that should happen once, before external consumers establish dependencies on the current placeholder values.
- Until the Basis Foundation establishes a canonical schema registry, changing the `$id` values introduces instability without benefit.

**Recommendation**: Do not change the `$id` values in this repository. Raise the canonical schema registry question with basis-architecture before any external tooling or consumer establishes a dependency on the current `$id` strings. Track this as `OPEN: schema-id-namespace` in the basis-architecture issue tracker.

### Schema versioning

The schemas themselves do not currently carry a version identifier (distinct from `AuditEvent.schema_version`). There is no mechanism for a consumer to determine which revision of, say, `decision-request.schema.json` is in use.

**Open question**: Should a `version` or `x-schema-version` annotation be added to the schemas to make schema revision explicit, independently of the `$schema` declaration?

This is not urgent while the schemas are pre-1.0 and breaking changes carry no compatibility obligation. It becomes important once consumers begin building against a specific schema revision.

See `docs/schema-versioning.md` for the full set of schema evolution rules, the breaking-change process, and all open versioning questions in one place.

---

## Relationship to basis-architecture

The compatibility rules in this document implement the principles defined in `docs/architecture/compatibility-philosophy.md` in basis-architecture. The governing document is the basis-architecture one; this document provides implementation-level detail specific to the schemas in this repository.

When an implementation constraint conflicts with an architectural rule about compatibility, raise the conflict in basis-architecture rather than resolving it here.
