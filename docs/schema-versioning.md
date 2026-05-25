# Schema Versioning

This document establishes the minimum safe compatibility discipline for schema evolution in basis-core. It defines which schema changes are breaking, which are additive, and what process is required before a breaking change can proceed.

This is **not** a full migration framework, a schema registry service, or a finalized versioning scheme. It captures the baseline rules that protect external consumers from accidental incompatible schema changes while those larger questions remain open.

Cross-references: `docs/schema-contracts.md` documents the stability rules and open questions for each schema. `docs/architecture/compatibility-philosophy.md` in basis-architecture establishes the governing rationale — this document operationalizes that rationale for the schemas in this repository. `docs/audit-model.md` and `docs/core-domain.md` describe the semantic context these schemas encode.

---

## What these rules protect

The four schemas in `schemas/` define external compatibility contracts:

| Schema | File | External consumers |
|---|---|---|
| DecisionRequest | `schemas/decision-request.schema.json` | Gateways, adapters, enforcement points submitting requests |
| DecisionResponse | `schemas/decision-response.schema.json` | Callers reading authorization decisions |
| AuditEvent | `schemas/audit-event.schema.json` | Audit pipeline, compliance reporters, forensic tools, stored records |
| Policy | `schemas/policy.schema.json` | Policy authoring systems, configuration loaders |

Changes to these schemas are felt by all consumers simultaneously. For `AuditEvent`, changes are also felt _retroactively_: stored records carry no mechanism for post-hoc field addition or renaming. A field rename produces a structural discontinuity in the audit record that no documentation fully resolves.

---

## Schema structure requirements

Every schema in `schemas/` must include the following top-level fields:

- `$schema` — declares the JSON Schema draft in use
- `$id` — opaque namespace identifier (see open questions)
- `title` — human-readable schema name
- `type` — the JSON type of the root object
- `additionalProperties: false` — the schema surface is explicit; unknown fields are rejected

`additionalProperties: false` is intentional. It ensures that every field that crosses the kernel boundary is declared explicitly, and that accidental or undeclared extension is caught at validation time rather than silently passed through.

The `tests/test_schema_versioning.py` test suite verifies these structural requirements and the required-field and enum snapshots described below.

---

## Breaking changes

The following changes to any schema in `schemas/` are breaking. They require architecture review and, except in unusual circumstances, an ADR in basis-architecture before proceeding.

**Field removal** — Removing a required or optional field that consumers depend on is always breaking. Required fields encode invariants; optional fields encode behaviors that consumers may have adopted.

**Field renaming** — Renaming a field is a breaking change to every consumer that references the old name, regardless of how the rename is documented. Audit records containing the old name are structurally incompatible with tooling that expects the new name.

**Field semantic change** — Changing what a field means — redefining `evaluated_by` from "rule that produced the decision" to "rule that was first evaluated," for example — is a breaking change even if the field name and type are unchanged. Semantic changes produce audit records that look correct but are not.

**Required field addition** — Adding a new required field breaks every producer that does not know about the new field. This is only safe if a compatibility default exists and all producers can be updated simultaneously — conditions that are rarely met in field deployments.

**Enum value removal** — Removing an enum value is breaking. Any record or payload that carried the removed value is now invalid against the new schema, and any consumer that handled the value by name is broken.

**Enum semantic redefinition** — Changing what an existing enum value means is breaking. The enum string `"denied"` must mean the same thing in every schema version.

**Pattern tightening** — Narrowing a `pattern` constraint to reject values that the prior pattern accepted is breaking. Any record or payload produced under the prior constraint may now fail validation.

**`additionalProperties` from `false` to `true`** — This loosens the contract: payloads that were previously rejected are now accepted. Consumers that rely on the strict rejection invariant are broken by this change.

---

## Additive changes

The following changes are generally additive and do not require a breaking-change review. They should still be accompanied by a changelog entry.

**New optional field** — Adding a field with defined absence semantics (consumers that receive a record without the field must not fail) is additive, provided the field is not required and the schema continues to accept payloads without it.

**New enum value** — Adding an enum value is additive, provided consumers that encounter an unrecognized value can handle it gracefully. Forward compatibility — tolerating unknown enum values without failure — is the producer's responsibility to design for and the consumer's responsibility to implement.

**Pattern loosening** — Accepting values that were previously rejected is loosening, which is additive in the sense that it does not break existing producers. However, loosening can weaken invariants that consumers rely on. Review whether the loosened pattern expands the accepted vocabulary in ways that are semantically coherent before treating it as purely additive.

---

## Schema version fields

### `AuditEvent.schema_version`

`AuditEvent` carries a `schema_version` field that identifies the schema revision in effect when the record was written. The current value is `"1.1"`. Consumers use this field to determine which optional fields are present in a record.

`schema_version` must always be populated when writing an `AuditEvent`. A record without `schema_version` is ambiguous for consumers that need to handle records from multiple schema revisions.

### Schema-level version annotation (open question)

The schemas themselves do not currently carry a version annotation (distinct from `AuditEvent.schema_version`). There is no mechanism for a tooling consumer to determine which revision of `decision-request.schema.json` is in use without inspecting the repository.

This is tracked as an open question below.

---

## Examples must stay valid

The `schemas/examples/` directory contains schema-valid reference examples for each schema. These files are validated by the test suite (`tests/test_schema_versioning.py` and `tests/test_schema_validation.py`) without modification.

Any schema change that causes a canonical example to fail validation is a signal that either the schema change is breaking, or the example needs to be updated to reflect the new schema's intended usage. Updating examples is not a substitute for documenting a breaking change.

---

## Breaking change process

When a breaking schema change is necessary:

1. **Raise for architecture review.** Breaking schema changes are cross-component compatibility events. They must be reviewed in basis-architecture before being applied in basis-core. Do not make breaking changes to `schemas/` without a corresponding architectural decision.

2. **File an ADR.** Per `docs/adr/README.md` in basis-architecture, a change that affects a compatibility surface requires an ADR documenting the rationale, the alternatives considered, and the migration path.

3. **Define the migration path before deploying.** A breaking schema change without a defined migration path is not deployable in an ecosystem where components update at different speeds. The migration path — how existing consumers and stored records are handled under the new schema — must be specified before the change is merged.

4. **Update the test snapshots deliberately.** The required-field and enum snapshots in `tests/test_schema_versioning.py` will need to be updated for a breaking change. This is intentional: the test failure is the signal. Update the snapshots as part of the breaking change, not as a cleanup step.

---

## Open questions

The following questions remain deliberately unresolved. They are tracked here and in basis-architecture to prevent accidental resolution through implementation choices.

### Schema `$id` namespace

All four schemas use `$id` values of the form `https://basis-core/schemas/{name}.schema.json`. This is not a resolvable URL — `basis-core` is not a registered domain. These values function as opaque namespace identifiers for JSON Schema tooling.

**Open question**: Should the `$id` values migrate to a stable, resolvable namespace such as `https://schemas.basis-foundation.org/core/v1/{name}.schema.json`?

`$id` migration would affect any tooling or schema that uses `$ref` pointers to these identifiers. It should happen once, before external consumers establish dependencies on the current placeholder values. **Do not change the `$id` values in this repository** until the canonical schema registry question is resolved in basis-architecture. Track this as `OPEN: schema-id-namespace`.

### Schema-level version annotation

The schemas do not carry a version annotation that lets a tooling consumer identify which schema revision is in use. `AuditEvent.schema_version` covers the record-level case; there is no equivalent for the schema files themselves.

**Open question**: Should a `version` or `x-schema-version` annotation be added to the schema files?

This is not urgent while schemas are pre-1.0. It becomes important once external consumers begin pinning to specific schema revisions. Track this as `OPEN: schema-file-version-annotation`.

### Semantic versioning operationalization

The basis-architecture compatibility philosophy describes how semantic versioning should work conceptually (major = breaking, minor = additive, patch = correction). The schemas in this repository do not yet carry version numbers, and there is no defined process for incrementing them when changes are made.

**Open question**: How are schema versions operationalized — how are they incremented, communicated, and enforced across the ecosystem?

This is not yet a blocking concern for basis-core while the ecosystem is pre-release. Track this as `OPEN: schema-semver-operationalization`.

### `AuditEvent.subject_type` model/schema alignment

The `audit-event.schema.json` restricts `subject_type` to the enum `[human, device, service, gateway, agent, null]`. The `AuditEvent` Python model accepts any string to remain forward-compatible with subject types not yet listed in the schema.

**Open question**: Should the model be tightened to mirror the schema enum, or should the schema be loosened to `type: ["string", "null"]` to match the model's open-string behavior?

See `docs/schema-contracts.md` for the full discussion. Track this as `OPEN: audit-subject-type-alignment`.

---

## Relationship to other documents

This document establishes the what and when of schema change discipline. For the why, see `docs/architecture/compatibility-philosophy.md` in basis-architecture — the governing rationale is documented there.

For the current state of each schema's stability, known model/schema misalignments, and open compatibility questions, see `docs/schema-contracts.md`.

For the evaluation semantics that the schemas encode, see `docs/evaluation-semantics.md`. Changes to evaluation semantics that require schema changes are doubly breaking: they affect both the behavioral contract and the data contract simultaneously.
