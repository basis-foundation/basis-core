"""
Schema compatibility snapshot tests.

These tests protect against accidental incompatible schema changes. They verify
structural requirements (presence of $schema, $id, title, type,
additionalProperties) and snapshot the required-field sets and critical enum
values that form the external compatibility contract of each schema.

When to update these tests
──────────────────────────
A failing snapshot test means a breaking change has occurred or is in progress.
Do not update a snapshot constant to make a test pass without first completing
the breaking-change process described in ``docs/schema-versioning.md``:

1. Architecture review in basis-architecture.
2. An ADR documenting rationale and migration path.
3. A deliberate update to the snapshot constant as part of that process.

Updating the constant without following that process hides the break.

See ``docs/schema-versioning.md`` for the full compatibility rules.
See ``docs/schema-contracts.md`` for per-schema stability notes and open
questions.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

try:
    from jsonschema import Draft202012Validator, FormatChecker, ValidationError

    JSONSCHEMA_AVAILABLE = True
except ImportError:  # pragma: no cover
    JSONSCHEMA_AVAILABLE = False

# ── Paths ────────────────────────────────────────────────────────────────────

SCHEMAS_DIR = Path(__file__).parent.parent / "schemas"
SCHEMA_EXAMPLES_DIR = SCHEMAS_DIR / "examples"

pytestmark = pytest.mark.skipif(
    not JSONSCHEMA_AVAILABLE,
    reason="jsonschema not installed; add 'jsonschema[format-nongpl]>=4.18' to dev deps",
)

# ── Compatibility snapshots ──────────────────────────────────────────────────
#
# These constants are the authoritative record of the current schema contract.
# They exist so that breaking changes produce explicit test failures rather than
# silent drift.  Update them only as part of the breaking-change process
# described in docs/schema-versioning.md.

# Known schema files. A new schema file added without updating this set will
# not be covered by the structural and snapshot tests.
KNOWN_SCHEMA_FILES: frozenset[str] = frozenset(
    {
        "audit-event.schema.json",
        "decision-request.schema.json",
        "decision-response.schema.json",
        "policy.schema.json",
    }
)

# Required fields by schema. Removing any of these from the schema is breaking.
REQUIRED_FIELDS: dict[str, frozenset[str]] = {
    "decision-request": frozenset({"request_id", "subject_id", "action", "timestamp"}),
    "decision-response": frozenset(
        {"request_id", "outcome", "reason", "evaluated_by", "timestamp"}
    ),
    "audit-event": frozenset({"event_id", "event_type", "action", "timestamp"}),
    "policy": frozenset({"policy_id", "policy_type", "version", "created_at"}),
}

# Critical enum values by (schema, JSON-pointer-style path).
# Removing any value from these enums is breaking.
ENUM_VALUES: dict[tuple[str, str], frozenset[str]] = {
    # DecisionResponse.outcome
    ("decision-response", "outcome"): frozenset({"allow", "deny", "not_applicable"}),
    # DecisionResponse.failure_reason (null excluded — it is a type, not an enum value)
    ("decision-response", "failure_reason"): frozenset(
        {"malformed_request", "policy_error", "audit_error", "internal_error"}
    ),
    # AuditEvent.event_type
    ("audit-event", "event_type"): frozenset(
        {
            "authorization_decision",
            "policy_change",
            "identity_event",
            "emergency_override",
            "adapter_event",
            "system_event",
        }
    ),
    # AuditEvent.outcome (null excluded)
    ("audit-event", "outcome"): frozenset({"allowed", "denied", "error"}),
    # AuditEvent.subject_type (null excluded; open alignment question — see
    # docs/schema-contracts.md "AuditEvent.subject_type enum vs. model open-string")
    ("audit-event", "subject_type"): frozenset({"human", "device", "service", "gateway", "agent"}),
    # AuditEvent.trace.evaluated_rules[].outcome
    ("audit-event", "trace.evaluated_rules[].outcome"): frozenset(
        {"allow", "deny", "not_applicable"}
    ),
    # Policy.policy_type
    ("policy", "policy_type"): frozenset(
        {
            "role_policy",
            "resource_type_policy",
            "action_policy",
            "composite_policy",
        }
    ),
    # Policy.evaluation_semantics
    ("policy", "evaluation_semantics"): frozenset({"deny_overrides"}),
    # Policy.rules[].rule_type
    ("policy", "rules[].rule_type"): frozenset({"role", "resource_type", "action"}),
    # Policy.rules[].permitted_resource_types items
    ("policy", "rules[].permitted_resource_types"): frozenset(
        {"hvac", "sensor", "zone", "device", "gateway"}
    ),
    # Policy.rules[].action_outcomes values
    ("policy", "rules[].action_outcomes"): frozenset({"allow", "deny", "not_applicable"}),
}

# ── Helpers ──────────────────────────────────────────────────────────────────


def load_schema(name: str) -> dict:  # type: ignore[type-arg]
    """Load a JSON Schema by base name (without .schema.json suffix)."""
    path = SCHEMAS_DIR / f"{name}.schema.json"
    return json.loads(path.read_text(encoding="utf-8"))


def validate(instance: object, schema: dict) -> None:  # type: ignore[type-arg]
    """Validate *instance* against *schema* using Draft 2020-12 with format checking."""
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    validator.validate(instance)


def enum_values_from_schema(schema: dict, field: str) -> frozenset[str]:  # type: ignore[type-arg]
    """
    Extract the enum values for a top-level field from a schema.

    Returns only string values (null/None is a type, not an enum value, and is
    handled by the type declaration rather than the enum list).
    """
    prop = schema.get("properties", {}).get(field, {})
    return frozenset(v for v in prop.get("enum", []) if v is not None)


# ══════════════════════════════════════════════════════════════════════════════
# Structural requirements
# ══════════════════════════════════════════════════════════════════════════════


class TestSchemaStructuralRequirements:
    """
    Every schema in schemas/ must carry the required structural markers.

    These tests verify the schema files themselves, not payloads. A schema that
    is missing $schema, $id, title, type, or additionalProperties: false is
    incomplete as an external compatibility contract.
    """

    @pytest.fixture(params=sorted(KNOWN_SCHEMA_FILES))
    def schema_file(self, request: pytest.FixtureRequest) -> tuple[str, dict]:  # type: ignore[type-arg]
        name = request.param
        path = SCHEMAS_DIR / name
        schema = json.loads(path.read_text(encoding="utf-8"))
        return name, schema

    def test_schema_file_exists(self, schema_file: tuple[str, dict]) -> None:  # type: ignore[type-arg]
        """Each known schema file must exist on disk."""
        name, _ = schema_file
        assert (SCHEMAS_DIR / name).exists(), f"Schema file not found: {name}"

    def test_has_dollar_schema(self, schema_file: tuple[str, dict]) -> None:  # type: ignore[type-arg]
        """$schema must be present — declares which JSON Schema draft governs."""
        _, schema = schema_file
        assert "$schema" in schema, "Schema is missing $schema"
        assert schema["$schema"], "$schema must be non-empty"

    def test_has_dollar_id(self, schema_file: tuple[str, dict]) -> None:  # type: ignore[type-arg]
        """$id must be present — serves as the opaque namespace identifier."""
        _, schema = schema_file
        assert "$id" in schema, "Schema is missing $id"
        assert schema["$id"], "$id must be non-empty"

    def test_has_title(self, schema_file: tuple[str, dict]) -> None:  # type: ignore[type-arg]
        """title must be present."""
        _, schema = schema_file
        assert "title" in schema, "Schema is missing title"
        assert schema["title"], "title must be non-empty"

    def test_has_type(self, schema_file: tuple[str, dict]) -> None:  # type: ignore[type-arg]
        """type must be present at the root level."""
        _, schema = schema_file
        assert "type" in schema, "Schema is missing type"

    def test_has_additional_properties_false(
        self,
        schema_file: tuple[str, dict],  # type: ignore[type-arg]
    ) -> None:
        """additionalProperties must be false — the schema surface must be explicit."""
        _, schema = schema_file
        assert schema.get("additionalProperties") is False, (
            "Schema must have additionalProperties: false. "
            "All fields that cross the kernel boundary must be declared explicitly."
        )

    def test_known_schema_files_are_complete(self) -> None:
        """
        All files matching *.schema.json in schemas/ must be in KNOWN_SCHEMA_FILES.

        A new schema file added without updating this set will not be covered by
        the structural and snapshot tests. This test catches that gap.
        """
        actual_files = frozenset(p.name for p in SCHEMAS_DIR.glob("*.schema.json"))
        unknown = actual_files - KNOWN_SCHEMA_FILES
        assert not unknown, (
            f"New schema files detected that are not in KNOWN_SCHEMA_FILES: {unknown}. "
            "Add them to the snapshot constants in this test file."
        )


# ══════════════════════════════════════════════════════════════════════════════
# Required-field snapshots
# ══════════════════════════════════════════════════════════════════════════════


class TestRequiredFieldSnapshots:
    """
    The required-field set for each schema is a compatibility contract.

    Removing a required field is a breaking change. These tests snapshot the
    required-field sets so that removals produce an explicit test failure rather
    than silent drift.
    """

    @pytest.mark.parametrize("schema_name", sorted(REQUIRED_FIELDS.keys()))
    def test_required_fields_are_present_in_schema(self, schema_name: str) -> None:
        """The schema must still declare at least the snapshotted required fields."""
        schema = load_schema(schema_name)
        actual_required = frozenset(schema.get("required", []))
        expected_required = REQUIRED_FIELDS[schema_name]
        missing = expected_required - actual_required
        assert not missing, (
            f"Breaking change detected in {schema_name}.schema.json: "
            f"required fields removed from schema: {missing}. "
            "See docs/schema-versioning.md before updating this snapshot."
        )

    @pytest.mark.parametrize("schema_name", sorted(REQUIRED_FIELDS.keys()))
    def test_required_fields_snapshot_matches_schema(self, schema_name: str) -> None:
        """
        The snapshotted required fields must match the schema exactly.

        A field added to ``required`` without updating the snapshot is not caught
        here — that is an additive change (adding a required field may itself be
        breaking, but that is caught by integration rather than this snapshot).
        This test primarily ensures the snapshot stays aligned with the schema so
        that readers can trust it as the authoritative record.
        """
        schema = load_schema(schema_name)
        actual_required = frozenset(schema.get("required", []))
        expected_required = REQUIRED_FIELDS[schema_name]
        new_required = actual_required - expected_required
        assert not new_required, (
            f"New required fields in {schema_name}.schema.json not reflected in "
            f"REQUIRED_FIELDS snapshot: {new_required}. "
            "Update the snapshot constant and verify this is an intentional change. "
            "Note: adding a required field is itself potentially breaking — "
            "see docs/schema-versioning.md."
        )


# ══════════════════════════════════════════════════════════════════════════════
# Enum value snapshots
# ══════════════════════════════════════════════════════════════════════════════


class TestEnumValueSnapshots:
    """
    Enum values on major compatibility surfaces are stability contracts.

    Removing an enum value is always breaking. These tests snapshot the current
    enum values so that removals produce an explicit test failure.

    Note: the snapshot keys use a simplified path notation (not JSON Pointer)
    for readability. Nested enums (e.g. trace.evaluated_rules[].outcome) are
    extracted by hand in the relevant test methods rather than through generic
    traversal, to keep the tests explicit and easy to follow.
    """

    # Top-level property enums — straightforward to extract from schema.properties
    TOP_LEVEL_ENUMS = {
        key: value for key, value in ENUM_VALUES.items() if "." not in key[1] and "[" not in key[1]
    }

    @pytest.mark.parametrize(
        "schema_name,field",
        sorted((s, f) for (s, f) in TOP_LEVEL_ENUMS),
    )
    def test_top_level_enum_values_preserved(self, schema_name: str, field: str) -> None:
        """Enum values at the top-level properties must not be removed."""
        schema = load_schema(schema_name)
        actual = enum_values_from_schema(schema, field)
        expected = ENUM_VALUES[(schema_name, field)]
        removed = expected - actual
        assert not removed, (
            f"Breaking change detected: enum values removed from "
            f"{schema_name}.schema.json properties.{field}.enum: {removed}. "
            "See docs/schema-versioning.md before updating this snapshot."
        )

    def test_audit_event_trace_evaluated_rules_outcome_enum(self) -> None:
        """AuditEvent trace.evaluated_rules[].outcome enum values must not be removed."""
        schema = load_schema("audit-event")
        trace_items = (
            schema.get("properties", {})
            .get("trace", {})
            .get("properties", {})
            .get("evaluated_rules", {})
            .get("items", {})
            .get("properties", {})
            .get("outcome", {})
        )
        actual = frozenset(v for v in trace_items.get("enum", []) if v is not None)
        expected = ENUM_VALUES[("audit-event", "trace.evaluated_rules[].outcome")]
        removed = expected - actual
        assert not removed, (
            f"Breaking change detected: enum values removed from "
            f"audit-event.schema.json trace.evaluated_rules[].outcome.enum: {removed}. "
            "See docs/schema-versioning.md before updating this snapshot."
        )

    def test_policy_rules_rule_type_enum(self) -> None:
        """Policy rules[].rule_type enum values must not be removed."""
        schema = load_schema("policy")
        rule_type = (
            schema.get("properties", {})
            .get("rules", {})
            .get("items", {})
            .get("properties", {})
            .get("rule_type", {})
        )
        actual = frozenset(v for v in rule_type.get("enum", []) if v is not None)
        expected = ENUM_VALUES[("policy", "rules[].rule_type")]
        removed = expected - actual
        assert not removed, (
            f"Breaking change detected: enum values removed from "
            f"policy.schema.json rules[].rule_type.enum: {removed}. "
            "See docs/schema-versioning.md before updating this snapshot."
        )

    def test_policy_rules_permitted_resource_types_enum(self) -> None:
        """Policy rules[].permitted_resource_types enum values must not be removed."""
        schema = load_schema("policy")
        items = (
            schema.get("properties", {})
            .get("rules", {})
            .get("items", {})
            .get("properties", {})
            .get("permitted_resource_types", {})
            .get("items", {})
        )
        actual = frozenset(v for v in items.get("enum", []) if v is not None)
        expected = ENUM_VALUES[("policy", "rules[].permitted_resource_types")]
        removed = expected - actual
        assert not removed, (
            f"Breaking change detected: enum values removed from "
            f"policy.schema.json rules[].permitted_resource_types.items.enum: {removed}. "
            "See docs/schema-versioning.md before updating this snapshot."
        )

    def test_policy_rules_action_outcomes_values_enum(self) -> None:
        """Policy rules[].action_outcomes values enum must not be removed."""
        schema = load_schema("policy")
        additional_props = (
            schema.get("properties", {})
            .get("rules", {})
            .get("items", {})
            .get("properties", {})
            .get("action_outcomes", {})
            .get("additionalProperties", {})
        )
        actual = frozenset(v for v in additional_props.get("enum", []) if v is not None)
        expected = ENUM_VALUES[("policy", "rules[].action_outcomes")]
        removed = expected - actual
        assert not removed, (
            f"Breaking change detected: enum values removed from "
            f"policy.schema.json rules[].action_outcomes.additionalProperties.enum: {removed}. "
            "See docs/schema-versioning.md before updating this snapshot."
        )


# ══════════════════════════════════════════════════════════════════════════════
# schema_version presence
# ══════════════════════════════════════════════════════════════════════════════


class TestSchemaVersionField:
    """
    AuditEvent must carry schema_version as a declared property.

    This field is how consumers determine which optional fields are present in a
    stored record. Its presence as a schema property is a structural requirement.
    """

    def test_audit_event_schema_version_property_exists(self) -> None:
        """audit-event.schema.json must declare schema_version as a property."""
        schema = load_schema("audit-event")
        assert "schema_version" in schema.get("properties", {}), (
            "audit-event.schema.json no longer declares schema_version as a property. "
            "This field is required for consumers to identify which schema revision "
            "produced a given record. See docs/schema-versioning.md."
        )

    def test_audit_event_schema_version_is_string_type(self) -> None:
        """schema_version must be declared as type string."""
        schema = load_schema("audit-event")
        prop = schema.get("properties", {}).get("schema_version", {})
        assert prop.get("type") == "string", (
            "audit-event.schema.json schema_version type changed from 'string'. "
            "This is a breaking change."
        )


# ══════════════════════════════════════════════════════════════════════════════
# Canonical example file validation
# ══════════════════════════════════════════════════════════════════════════════


class TestCanonicalExampleFiles:
    """
    The canonical examples in schemas/examples/ must remain valid against their
    schemas at all times.

    An example that fails validation after a schema change signals one of two
    things: either the schema change is breaking (and the example exposes it),
    or the example must be updated to reflect the new intended usage. In both
    cases, the failure is intentional — it surfaces the impact of the change.
    """

    @pytest.mark.parametrize(
        "example_file,schema_name",
        [
            ("decision-request.json", "decision-request"),
            ("decision-response.json", "decision-response"),
            ("audit-event.json", "audit-event"),
            ("policy.json", "policy"),
        ],
    )
    def test_example_validates_against_schema(self, example_file: str, schema_name: str) -> None:
        """Each canonical example must pass strict schema validation."""
        example_path = SCHEMA_EXAMPLES_DIR / example_file
        if not example_path.exists():
            pytest.skip(f"Example file not found: {example_path}")
        example = json.loads(example_path.read_text(encoding="utf-8"))
        schema = load_schema(schema_name)
        try:
            validate(example, schema)
        except ValidationError as exc:
            pytest.fail(
                f"schemas/examples/{example_file} no longer validates against "
                f"{schema_name}.schema.json.\n"
                f"Validation error: {exc.message}\n"
                "Either the schema change is breaking (the example reveals it), or "
                "the example must be updated. See docs/schema-versioning.md."
            )

    def test_audit_event_example_has_schema_version(self) -> None:
        """The canonical audit-event example must include schema_version."""
        example_path = SCHEMA_EXAMPLES_DIR / "audit-event.json"
        if not example_path.exists():
            pytest.skip("audit-event.json example not found")
        example = json.loads(example_path.read_text(encoding="utf-8"))
        assert "schema_version" in example, (
            "The canonical audit-event example does not include schema_version. "
            "schema_version must always be populated in AuditEvent records. "
            "See docs/schema-versioning.md."
        )
        assert example["schema_version"], "schema_version must be a non-empty string"

    def test_audit_event_example_schema_version_value(self) -> None:
        """The canonical audit-event example must carry the current schema_version."""
        example_path = SCHEMA_EXAMPLES_DIR / "audit-event.json"
        if not example_path.exists():
            pytest.skip("audit-event.json example not found")
        example = json.loads(example_path.read_text(encoding="utf-8"))
        # Current schema_version is "1.1" — update this when the version increments.
        # Updating this value is intentional and expected as part of a schema revision.
        assert example.get("schema_version") == "1.1", (
            f"audit-event example schema_version is {example.get('schema_version')!r}, "
            f"expected '1.1'. If the schema version was intentionally incremented, "
            "update this assertion as part of the schema revision process."
        )
