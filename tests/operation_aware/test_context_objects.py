"""
tests/operation_aware/test_context_objects.py — tests for
`basis_core.domain.operation_aware` (Milestone 2, PR 7 of
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`:
"Operation-aware context value objects").

Covers `OperationAwareLocation`, `OperationAwareDevice`,
`OperationAwareProtocolContext`, `OperationAwareSafetyContext`,
`OperationAwareEnvironmentContext`, and `OperationAwareRiskContext`
construction, validation, immutability, equality, hashing, and deterministic
representation — cross-checked against the vendored `basis-schemas` v0.2.0
`operation-aware-decision-request` contract's six nested `*_shape` blocks via
the existing test-only loader (`tests/helpers/operation_aware_contracts.py`).

These models carry normalized, supplied context only. This file tests
context *shape* only: construction, validation, immutability, schema
alignment, and data-minimization. It does not test, and must never test,
whether a context value is trustworthy, sufficient, safe, risky, or policy
compliant — none of that behavior exists in this module or this PR.

Nested valid-example extraction: the vendored contract's own top-level
`examples.valid` list is request-shaped, not context-object-shaped. Two of
its four examples cleanly isolate the six context objects this PR
implements without altering their content: example index 2 ("OT
operation-rich request") carries `location`, `device`, and
`protocol_context`; example index 3 ("full contextual request") carries
`safety_context`, `environment_context`, and `risk_context`. This file reads
those two examples' nested objects directly rather than re-typing synthetic
data, per the roadmap's "create focused test data derived directly from the
published shape and document that choice" guidance. The one nested-object
invalid example the top-level contract publishes (an unknown `country` key
under `location`) is reused directly for `OperationAwareLocation`; the
remaining invalid-construction cases are constructed directly, parametrized
from each shape's own published field patterns.

Does not test any later, not-yet-implemented operation-aware model
(`OperationAwareDecisionRequest`, policy, trace, audit) — see
`tests/operation_aware/README.md`'s scope boundaries.
"""

from __future__ import annotations

import math

import pytest
from pydantic import ValidationError

from basis_core.domain.operation_aware import (
    _OPEN_IDENTIFIER_RE,
    OperationAwareDevice,
    OperationAwareEnvironmentContext,
    OperationAwareLocation,
    OperationAwareProtocolContext,
    OperationAwareRiskContext,
    OperationAwareSafetyContext,
)
from tests.helpers.operation_aware_contracts import (
    load_contract,
    require_mapping_field,
    require_sequence_field,
    require_string_field,
)

_CONTRACT_NAME = "operation-aware-decision-request"
_ROOT_SECTION = "operation_aware_decision_request"


def _load_request_document() -> dict[str, object]:
    return load_contract(_CONTRACT_NAME)


def _load_shape(shape_name: str) -> dict[str, object]:
    document = _load_request_document()
    root = require_mapping_field(document, _ROOT_SECTION, context=_CONTRACT_NAME)
    return require_mapping_field(root, shape_name, context=_ROOT_SECTION)


def _shape_field_pattern(shape: dict[str, object], field_id: str) -> str | None:
    fields = require_sequence_field(shape, "fields", context="shape")
    by_id = {
        require_string_field(f, "id", context="shape.field"): f  # type: ignore[misc]
        for f in fields  # type: ignore[union-attr]
    }
    field = by_id[field_id]
    assert isinstance(field, dict)
    pattern = field.get("pattern")
    if pattern is None:
        return None
    assert isinstance(pattern, str)
    return pattern


def _nested_valid_examples() -> list[dict[str, object]]:
    document = _load_request_document()
    root = require_mapping_field(document, _ROOT_SECTION, context=_CONTRACT_NAME)
    examples = require_mapping_field(root, "examples", context=_ROOT_SECTION)
    return require_sequence_field(examples, "valid", context=f"{_ROOT_SECTION}.examples")  # type: ignore[return-value]


def _nested_invalid_examples() -> list[dict[str, object]]:
    document = _load_request_document()
    root = require_mapping_field(document, _ROOT_SECTION, context=_CONTRACT_NAME)
    examples = require_mapping_field(root, "examples", context=_ROOT_SECTION)
    return require_sequence_field(examples, "invalid", context=f"{_ROOT_SECTION}.examples")  # type: ignore[return-value]


# The two vendored request examples that cleanly isolate this PR's six
# context objects (see module docstring). Indices are stable: they match
# the vendored contract's published example ordering.
_OT_OPERATION_RICH_EXAMPLE_INDEX = 2
_FULL_CONTEXTUAL_EXAMPLE_INDEX = 3


# ══════════════════════════════════════════════════════════════════════════
# OperationAwareLocation
# ══════════════════════════════════════════════════════════════════════════


class TestOperationAwareLocationSchemaAlignment:
    def test_optional_field_names_match_contract(self) -> None:
        shape = _load_shape("location_shape")
        assert "required" not in shape
        optional = set(require_sequence_field(shape, "optional", context="location_shape"))
        assert set(OperationAwareLocation.model_fields) == optional

    def test_all_fields_are_individually_optional(self) -> None:
        for info in OperationAwareLocation.model_fields.values():
            assert not info.is_required()


class TestOperationAwareLocationConstruction:
    def test_default_construction_is_all_none(self) -> None:
        location = OperationAwareLocation()
        assert location.site_id is None
        assert location.building_id is None
        assert location.zone_id is None
        assert location.area_id is None

    def test_full_construction(self) -> None:
        location = OperationAwareLocation(
            site_id="west-campus", building_id="bldg-3", zone_id="zone-a", area_id="area-1"
        )
        assert location.site_id == "west-campus"
        assert location.zone_id == "zone-a"

    def test_vendored_nested_example_constructs(self) -> None:
        example = _nested_valid_examples()[_OT_OPERATION_RICH_EXAMPLE_INDEX]
        nested = example["location"]
        assert isinstance(nested, dict)
        location = OperationAwareLocation(**nested)
        assert location.site_id == nested["site_id"]
        assert location.building_id == nested["building_id"]
        assert location.zone_id == nested["zone_id"]

    def test_vendored_invalid_nested_example_is_rejected(self) -> None:
        # "malformed nested structure (unknown key in location)"
        entries = _nested_invalid_examples()
        matches = [e for e in entries if "location" in e["reason"]]  # type: ignore[operator]
        assert len(matches) == 1
        value = matches[0]["value"]
        assert isinstance(value, dict)
        nested = value["location"]
        assert isinstance(nested, dict)
        with pytest.raises(ValidationError):
            OperationAwareLocation(**nested)

    @pytest.mark.parametrize("field_name", ["site_id", "building_id", "zone_id", "area_id"])
    def test_empty_identifier_is_rejected(self, field_name: str) -> None:
        with pytest.raises(ValidationError):
            OperationAwareLocation(**{field_name: ""})

    @pytest.mark.parametrize("field_name", ["site_id", "building_id", "zone_id", "area_id"])
    def test_wrong_type_identifier_is_rejected(self, field_name: str) -> None:
        with pytest.raises(ValidationError):
            OperationAwareLocation(**{field_name: 12345})

    def test_unknown_field_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwareLocation(country="unsupported-nested-key")  # type: ignore[call-arg]


class TestOperationAwareLocationImmutabilityAndEquality:
    def test_frozen_rejects_attribute_assignment(self) -> None:
        location = OperationAwareLocation(site_id="west-campus")
        with pytest.raises(ValidationError):
            location.site_id = "changed"  # type: ignore[misc]

    def test_equality_is_value_based(self) -> None:
        assert OperationAwareLocation(site_id="a") == OperationAwareLocation(site_id="a")

    def test_hashable(self) -> None:
        a = OperationAwareLocation(site_id="a")
        b = OperationAwareLocation(site_id="a")
        assert hash(a) == hash(b)
        assert len({a, b}) == 1

    def test_deterministic_repr(self) -> None:
        location = OperationAwareLocation(site_id="west-campus")
        assert "OperationAwareLocation(" in repr(location)
        assert "west-campus" in repr(location)


# ══════════════════════════════════════════════════════════════════════════
# OperationAwareDevice
# ══════════════════════════════════════════════════════════════════════════


class TestOperationAwareDeviceSchemaAlignment:
    def test_optional_field_names_match_contract(self) -> None:
        shape = _load_shape("device_shape")
        assert "required" not in shape
        optional = set(require_sequence_field(shape, "optional", context="device_shape"))
        assert set(OperationAwareDevice.model_fields) == optional

    def test_device_class_pattern_matches_contract(self) -> None:
        shape = _load_shape("device_shape")
        pattern = _shape_field_pattern(shape, "device_class")
        assert pattern == r"^[a-z][a-z0-9_-]*$"
        assert _OPEN_IDENTIFIER_RE.pattern == pattern


class TestOperationAwareDeviceConstruction:
    def test_default_construction_is_all_none(self) -> None:
        device = OperationAwareDevice()
        assert device.device_id is None
        assert device.device_class is None

    def test_vendored_nested_example_constructs(self) -> None:
        example = _nested_valid_examples()[_OT_OPERATION_RICH_EXAMPLE_INDEX]
        nested = example["device"]
        assert isinstance(nested, dict)
        device = OperationAwareDevice(**nested)
        assert device.device_id == nested["device_id"]
        assert device.device_class == nested["device_class"]

    def test_empty_device_id_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwareDevice(device_id="")

    @pytest.mark.parametrize(
        "device_class,description",
        [
            ("Controller", "uppercase"),
            ("", "empty"),
            ("-controller", "leading hyphen"),
            ("controller ", "trailing whitespace, not a valid identifier char"),
        ],
    )
    def test_invalid_device_class_is_rejected(self, device_class: str, description: str) -> None:
        with pytest.raises(ValidationError):
            OperationAwareDevice(device_class=device_class)

    @pytest.mark.parametrize("device_class", ["controller", "sensor", "actuator", "gateway"])
    def test_valid_device_class_labels_construct(self, device_class: str) -> None:
        device = OperationAwareDevice(device_class=device_class)
        assert device.device_class == device_class

    def test_unknown_field_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwareDevice(firmware_version="1.2.3")  # type: ignore[call-arg]


class TestOperationAwareDeviceImmutabilityAndEquality:
    def test_frozen_rejects_attribute_assignment(self) -> None:
        device = OperationAwareDevice(device_id="ahu-14")
        with pytest.raises(ValidationError):
            device.device_id = "changed"  # type: ignore[misc]

    def test_equality_is_value_based(self) -> None:
        assert OperationAwareDevice(device_id="ahu-14") == OperationAwareDevice(device_id="ahu-14")

    def test_hashable(self) -> None:
        a = OperationAwareDevice(device_id="ahu-14")
        b = OperationAwareDevice(device_id="ahu-14")
        assert hash(a) == hash(b)


# ══════════════════════════════════════════════════════════════════════════
# OperationAwareProtocolContext
# ══════════════════════════════════════════════════════════════════════════


class TestOperationAwareProtocolContextSchemaAlignment:
    def test_optional_field_names_match_contract(self) -> None:
        shape = _load_shape("protocol_context_shape")
        assert "required" not in shape
        optional = set(require_sequence_field(shape, "optional", context="protocol_context_shape"))
        assert set(OperationAwareProtocolContext.model_fields) == optional

    def test_protocol_pattern_matches_contract(self) -> None:
        shape = _load_shape("protocol_context_shape")
        pattern = _shape_field_pattern(shape, "protocol")
        assert pattern == r"^[a-z][a-z0-9_-]*$"
        assert _OPEN_IDENTIFIER_RE.pattern == pattern

    def test_operation_field_has_no_pattern(self) -> None:
        shape = _load_shape("protocol_context_shape")
        assert _shape_field_pattern(shape, "operation") is None


class TestOperationAwareProtocolContextConstruction:
    def test_default_construction_is_all_none(self) -> None:
        ctx = OperationAwareProtocolContext()
        assert ctx.protocol is None
        assert ctx.operation is None

    def test_vendored_nested_example_constructs(self) -> None:
        example = _nested_valid_examples()[_OT_OPERATION_RICH_EXAMPLE_INDEX]
        nested = example["protocol_context"]
        assert isinstance(nested, dict)
        ctx = OperationAwareProtocolContext(**nested)
        assert ctx.protocol == nested["protocol"]
        assert ctx.operation == nested["operation"]

    @pytest.mark.parametrize(
        "protocol",
        ["modbus", "bacnet", "opcua", "mqtt", "dnp3", "iec61850", "knx", "niagara", "rest"],
    )
    def test_all_nine_published_adapter_protocol_labels_are_accepted(self, protocol: str) -> None:
        # Remains protocol-agnostic: accepted purely as an opaque label
        # matching the open pattern, not because this type understands any
        # of these nine protocols.
        ctx = OperationAwareProtocolContext(protocol=protocol)
        assert ctx.protocol == protocol

    @pytest.mark.parametrize(
        "protocol,description",
        [("BACnet", "uppercase"), ("", "empty"), ("bacnet ip", "contains a space")],
    )
    def test_invalid_protocol_is_rejected(self, protocol: str, description: str) -> None:
        with pytest.raises(ValidationError):
            OperationAwareProtocolContext(protocol=protocol)

    def test_empty_operation_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwareProtocolContext(operation="")

    def test_free_form_operation_name_is_not_pattern_constrained(self) -> None:
        ctx = OperationAwareProtocolContext(operation="WriteProperty")
        assert ctx.operation == "WriteProperty"

    def test_unknown_field_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwareProtocolContext(raw_protocol_payload="0x0300000A")  # type: ignore[call-arg]


class TestOperationAwareProtocolContextImmutabilityAndEquality:
    def test_frozen_rejects_attribute_assignment(self) -> None:
        ctx = OperationAwareProtocolContext(protocol="bacnet")
        with pytest.raises(ValidationError):
            ctx.protocol = "modbus"  # type: ignore[misc]

    def test_equality_is_value_based(self) -> None:
        assert OperationAwareProtocolContext(protocol="bacnet") == OperationAwareProtocolContext(
            protocol="bacnet"
        )


# ══════════════════════════════════════════════════════════════════════════
# OperationAwareSafetyContext
# ══════════════════════════════════════════════════════════════════════════


class TestOperationAwareSafetyContextSchemaAlignment:
    def test_optional_field_names_match_contract(self) -> None:
        shape = _load_shape("safety_context_shape")
        assert "required" not in shape
        optional = set(require_sequence_field(shape, "optional", context="safety_context_shape"))
        assert set(OperationAwareSafetyContext.model_fields) == optional

    @pytest.mark.parametrize("field_id", ["mode", "classification"])
    def test_pattern_fields_match_contract(self, field_id: str) -> None:
        shape = _load_shape("safety_context_shape")
        pattern = _shape_field_pattern(shape, field_id)
        assert pattern == r"^[a-z][a-z0-9_-]*$"
        assert _OPEN_IDENTIFIER_RE.pattern == pattern


class TestOperationAwareSafetyContextConstruction:
    def test_default_construction(self) -> None:
        ctx = OperationAwareSafetyContext()
        assert ctx.mode is None
        assert ctx.classification is None
        assert ctx.constraint_ids == ()

    def test_vendored_nested_example_constructs(self) -> None:
        example = _nested_valid_examples()[_FULL_CONTEXTUAL_EXAMPLE_INDEX]
        nested = example["safety_context"]
        assert isinstance(nested, dict)
        ctx = OperationAwareSafetyContext(**nested)
        assert ctx.mode == nested["mode"]
        assert ctx.classification == nested["classification"]
        assert ctx.constraint_ids == tuple(nested["constraint_ids"])  # type: ignore[arg-type]

    @pytest.mark.parametrize("field_id", ["mode", "classification"])
    def test_invalid_label_is_rejected(self, field_id: str) -> None:
        with pytest.raises(ValidationError):
            OperationAwareSafetyContext(**{field_id: "Invalid Label"})

    def test_constraint_ids_defaults_empty_and_is_a_tuple(self) -> None:
        ctx = OperationAwareSafetyContext()
        assert isinstance(ctx.constraint_ids, tuple)

    def test_constraint_ids_accepts_a_list_and_stores_immutable_tuple(self) -> None:
        source = ["lockout-tagout-active", "second-constraint"]
        ctx = OperationAwareSafetyContext(constraint_ids=source)
        assert ctx.constraint_ids == ("lockout-tagout-active", "second-constraint")
        # Mutating the caller's original list must not affect the model.
        source.append("mutated-after-construction")
        assert ctx.constraint_ids == ("lockout-tagout-active", "second-constraint")

    def test_constraint_ids_rejects_non_string_items(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwareSafetyContext(constraint_ids=[123])  # type: ignore[list-item]

    def test_unknown_field_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwareSafetyContext(interlock_bypass_code="1234")  # type: ignore[call-arg]


class TestOperationAwareSafetyContextImmutabilityAndEquality:
    def test_frozen_rejects_attribute_assignment(self) -> None:
        ctx = OperationAwareSafetyContext(mode="interlock-engaged")
        with pytest.raises(ValidationError):
            ctx.mode = "changed"  # type: ignore[misc]

    def test_frozen_tuple_field_cannot_be_mutated_in_place(self) -> None:
        ctx = OperationAwareSafetyContext(constraint_ids=["a"])
        with pytest.raises(AttributeError):
            ctx.constraint_ids.append("b")  # type: ignore[attr-defined]

    def test_equality_is_value_based(self) -> None:
        a = OperationAwareSafetyContext(mode="interlock-engaged", constraint_ids=["a"])
        b = OperationAwareSafetyContext(mode="interlock-engaged", constraint_ids=["a"])
        assert a == b

    def test_hashable(self) -> None:
        a = OperationAwareSafetyContext(mode="interlock-engaged", constraint_ids=["a"])
        b = OperationAwareSafetyContext(mode="interlock-engaged", constraint_ids=["a"])
        assert hash(a) == hash(b)


# ══════════════════════════════════════════════════════════════════════════
# OperationAwareEnvironmentContext
# ══════════════════════════════════════════════════════════════════════════


class TestOperationAwareEnvironmentContextSchemaAlignment:
    def test_optional_field_names_match_contract(self) -> None:
        shape = _load_shape("environment_context_shape")
        assert "required" not in shape
        optional = set(
            require_sequence_field(shape, "optional", context="environment_context_shape")
        )
        assert set(OperationAwareEnvironmentContext.model_fields) == optional

    def test_mode_pattern_matches_contract(self) -> None:
        shape = _load_shape("environment_context_shape")
        pattern = _shape_field_pattern(shape, "mode")
        assert pattern == r"^[a-z][a-z0-9_-]*$"


class TestOperationAwareEnvironmentContextConstruction:
    def test_default_construction(self) -> None:
        ctx = OperationAwareEnvironmentContext()
        assert ctx.mode is None
        assert ctx.condition_ids == ()

    def test_vendored_nested_example_constructs(self) -> None:
        example = _nested_valid_examples()[_FULL_CONTEXTUAL_EXAMPLE_INDEX]
        nested = example["environment_context"]
        assert isinstance(nested, dict)
        ctx = OperationAwareEnvironmentContext(**nested)
        assert ctx.mode == nested["mode"]
        assert ctx.condition_ids == tuple(nested["condition_ids"])  # type: ignore[arg-type]

    def test_invalid_mode_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwareEnvironmentContext(mode="Maintenance Mode")

    def test_condition_ids_accepts_a_list_and_stores_immutable_tuple(self) -> None:
        source = ["scheduled-window-open"]
        ctx = OperationAwareEnvironmentContext(condition_ids=source)
        source.append("mutated-after-construction")
        assert ctx.condition_ids == ("scheduled-window-open",)

    def test_condition_ids_rejects_non_string_items(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwareEnvironmentContext(condition_ids=[True])  # type: ignore[list-item]

    def test_unknown_field_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwareEnvironmentContext(degraded_connectivity=True)  # type: ignore[call-arg]


class TestOperationAwareEnvironmentContextImmutabilityAndEquality:
    def test_frozen_rejects_attribute_assignment(self) -> None:
        ctx = OperationAwareEnvironmentContext(mode="maintenance_mode")
        with pytest.raises(ValidationError):
            ctx.mode = "changed"  # type: ignore[misc]

    def test_equality_is_value_based(self) -> None:
        assert OperationAwareEnvironmentContext(
            mode="maintenance_mode"
        ) == OperationAwareEnvironmentContext(mode="maintenance_mode")


# ══════════════════════════════════════════════════════════════════════════
# OperationAwareRiskContext
# ══════════════════════════════════════════════════════════════════════════


class TestOperationAwareRiskContextSchemaAlignment:
    def test_optional_field_names_match_contract(self) -> None:
        shape = _load_shape("risk_context_shape")
        assert "required" not in shape
        optional = set(require_sequence_field(shape, "optional", context="risk_context_shape"))
        assert set(OperationAwareRiskContext.model_fields) == optional

    def test_classification_pattern_matches_contract(self) -> None:
        shape = _load_shape("risk_context_shape")
        pattern = _shape_field_pattern(shape, "classification")
        assert pattern == r"^[a-z][a-z0-9_-]*$"

    def test_score_field_has_no_pattern_or_declared_bounds(self) -> None:
        shape = _load_shape("risk_context_shape")
        assert _shape_field_pattern(shape, "score") is None


class TestOperationAwareRiskContextConstruction:
    def test_default_construction(self) -> None:
        ctx = OperationAwareRiskContext()
        assert ctx.classification is None
        assert ctx.score is None

    def test_vendored_nested_example_constructs(self) -> None:
        example = _nested_valid_examples()[_FULL_CONTEXTUAL_EXAMPLE_INDEX]
        nested = example["risk_context"]
        assert isinstance(nested, dict)
        ctx = OperationAwareRiskContext(**nested)
        assert ctx.classification == nested["classification"]
        assert ctx.score == nested["score"]

    def test_invalid_classification_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwareRiskContext(classification="Elevated")

    @pytest.mark.parametrize("score", [0.0, 0.62, 1.0, -3.5, 100])
    def test_valid_numeric_scores_construct(self, score: float) -> None:
        ctx = OperationAwareRiskContext(score=score)
        assert ctx.score == score

    def test_boolean_score_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwareRiskContext(score=True)  # type: ignore[arg-type]

    @pytest.mark.parametrize("score", [math.nan, math.inf, -math.inf])
    def test_non_finite_score_is_rejected(self, score: float) -> None:
        with pytest.raises(ValidationError):
            OperationAwareRiskContext(score=score)

    def test_no_bounds_are_enforced_on_score(self) -> None:
        # The contract defines no bounds/scale/calculation method — a large
        # or negative value is not itself invalid.
        ctx = OperationAwareRiskContext(score=-999.0)
        assert ctx.score == -999.0

    def test_unknown_field_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OperationAwareRiskContext(confidence=0.97)  # type: ignore[call-arg]


class TestOperationAwareRiskContextImmutabilityAndEquality:
    def test_frozen_rejects_attribute_assignment(self) -> None:
        ctx = OperationAwareRiskContext(score=0.62)
        with pytest.raises(ValidationError):
            ctx.score = 0.1  # type: ignore[misc]

    def test_equality_is_value_based(self) -> None:
        assert OperationAwareRiskContext(
            classification="elevated", score=0.62
        ) == OperationAwareRiskContext(classification="elevated", score=0.62)

    def test_hashable(self) -> None:
        a = OperationAwareRiskContext(classification="elevated", score=0.62)
        b = OperationAwareRiskContext(classification="elevated", score=0.62)
        assert hash(a) == hash(b)
