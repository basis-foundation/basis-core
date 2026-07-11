"""
tests/operation_aware/test_evidence.py — tests for
`basis_core.domain.evidence` (Milestone 2, PR 6 of
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`:
"Evidence-reference models").

Covers `EvidenceDigest`, `IdentityEvidenceReference`, and
`AdapterEvidenceReference` construction, validation, immutability, equality,
hashing, and deterministic representation — cross-checked against the
vendored `basis-schemas` v0.2.0 `identity-evidence-reference` and
`adapter-evidence-reference` contract fixtures via the existing test-only
loader (`tests/helpers/operation_aware_contracts.py`).

These models are bounded *references* to evidence produced outside the
kernel. This file tests reference *shape* only: construction, validation,
immutability, schema alignment, and data-minimization (no raw-evidence-
shaped field can be constructed). It does not test, and must never test,
evidence authenticity, cryptographic verification, digest computation, or
trust establishment — none of that exists in this module or this PR.

Does not test any later, not-yet-implemented operation-aware model (context
objects, request/response, policy, trace, audit) — see
`tests/operation_aware/README.md`'s scope boundaries.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from basis_core.domain.evidence import (
    _DIGEST_ALGORITHM_RE,
    _DIGEST_VALUE_RE,
    AdapterEvidenceReference,
    EvidenceDigest,
    IdentityEvidenceReference,
)
from basis_core.domain.operation_aware_vocabulary import RedactionClassification
from tests.helpers.operation_aware_contracts import (
    load_contract,
    require_mapping_field,
    require_sequence_field,
    require_string_field,
)

# A structurally valid digest, reused across tests that need one but are not
# themselves testing digest validation.
_VALID_DIGEST = {
    "algorithm": "sha-256",
    "value": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
}

# Field names this PR's contracts explicitly forbid — raw evidence, tokens,
# and credentials must never be constructible on either model. Combines the
# fields named in the roadmap brief with the fields the vendored contracts'
# own invalid examples exercise.
_RAW_EVIDENCE_FIELD_NAMES = [
    "access_token",
    "refresh_token",
    "id_token",
    "authorization_header",
    "password",
    "client_secret",
    "private_key",
    "raw_claims",
    "raw_token",
    "raw_protocol_payload",
    "unredacted_device_secret",
]


def _valid_examples(contract_name: str, section_name: str) -> list[dict[str, object]]:
    document = load_contract(contract_name)
    section = require_mapping_field(document, section_name, context=contract_name)
    examples = require_mapping_field(section, "examples", context=f"{contract_name}.{section_name}")
    return require_sequence_field(examples, "valid", context=f"{contract_name}...examples")  # type: ignore[return-value]


def _invalid_examples(contract_name: str, section_name: str) -> list[dict[str, object]]:
    document = load_contract(contract_name)
    section = require_mapping_field(document, section_name, context=contract_name)
    examples = require_mapping_field(section, "examples", context=f"{contract_name}.{section_name}")
    return require_sequence_field(examples, "invalid", context=f"{contract_name}...examples")  # type: ignore[return-value]


# ══════════════════════════════════════════════════════════════════════════
# EvidenceDigest
# ══════════════════════════════════════════════════════════════════════════


class TestEvidenceDigestPatternsAlignWithContracts:
    @pytest.mark.parametrize(
        "contract_name,section_name",
        [
            ("identity-evidence-reference", "identity_evidence_reference"),
            ("adapter-evidence-reference", "adapter_evidence_reference"),
        ],
    )
    def test_algorithm_and_value_patterns_match_vendored_contract(
        self, contract_name: str, section_name: str
    ) -> None:
        document = load_contract(contract_name)
        section = require_mapping_field(document, section_name, context=contract_name)
        digest_shape = require_mapping_field(
            section, "evidence_digest_shape", context=f"{contract_name}.{section_name}"
        )
        fields = require_sequence_field(
            digest_shape, "fields", context=f"{contract_name}.{section_name}.evidence_digest_shape"
        )
        by_id = {
            require_string_field(f, "id", context="evidence_digest_shape.field"): f
            for f in fields  # type: ignore[arg-type]
        }
        algorithm_pattern = require_string_field(
            by_id["algorithm"],
            "pattern",
            context="evidence_digest_shape.algorithm",  # type: ignore[arg-type]
        )
        value_pattern = require_string_field(
            by_id["value"],
            "pattern",
            context="evidence_digest_shape.value",  # type: ignore[arg-type]
        )
        assert algorithm_pattern == r"^[a-z][a-z0-9]*(-[a-z0-9]+)*$"
        assert value_pattern == r"^[a-f0-9]+$"
        assert _DIGEST_ALGORITHM_RE.pattern == algorithm_pattern
        assert _DIGEST_VALUE_RE.pattern == value_pattern

    def test_both_contracts_publish_byte_identical_digest_shape(self) -> None:
        # identity-evidence-reference.md and adapter-evidence-reference.md
        # document this nesting as "identical to identity-evidence-
        # reference's evidence_digest_shape" — confirm that claim directly.
        identity_doc = load_contract("identity-evidence-reference")
        adapter_doc = load_contract("adapter-evidence-reference")
        identity_shape = require_mapping_field(
            require_mapping_field(
                identity_doc, "identity_evidence_reference", context="identity-evidence-reference"
            ),
            "evidence_digest_shape",
            context="identity_evidence_reference",
        )
        adapter_shape = require_mapping_field(
            require_mapping_field(
                adapter_doc, "adapter_evidence_reference", context="adapter-evidence-reference"
            ),
            "evidence_digest_shape",
            context="adapter_evidence_reference",
        )
        assert identity_shape == adapter_shape


class TestEvidenceDigestConstruction:
    def test_valid_digest_constructs(self) -> None:
        digest = EvidenceDigest(**_VALID_DIGEST)
        assert digest.algorithm == "sha-256"
        assert digest.value == _VALID_DIGEST["value"]

    @pytest.mark.parametrize("algorithm", ["sha-256", "sha3-256", "blake2b", "a"])
    def test_valid_algorithm_labels_construct(self, algorithm: str) -> None:
        EvidenceDigest(algorithm=algorithm, value="ab")

    @pytest.mark.parametrize(
        "algorithm,description",
        [
            ("SHA256", "uppercase"),
            ("", "empty"),
            ("-sha256", "leading hyphen"),
            ("sha256-", "trailing hyphen"),
            ("sha--256", "doubled hyphen"),
        ],
    )
    def test_invalid_algorithm_labels_are_rejected(self, algorithm: str, description: str) -> None:
        with pytest.raises(ValidationError):
            EvidenceDigest(algorithm=algorithm, value="ab")

    @pytest.mark.parametrize(
        "value,description",
        [
            ("", "empty"),
            ("sha256:9f86d081", "colon-prefixed, not bare hex"),
            ("0x9f86d081", "0x-prefixed"),
            ("9F86D081", "uppercase hex"),
            ("9f86 d081", "contains whitespace"),
            ("not-hex-at-all", "non-hex characters"),
        ],
    )
    def test_invalid_digest_values_are_rejected(self, value: str, description: str) -> None:
        with pytest.raises(ValidationError):
            EvidenceDigest(algorithm="sha-256", value=value)

    def test_unknown_field_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            EvidenceDigest(algorithm="sha-256", value="ab", extra_field="x")  # type: ignore[call-arg]

    def test_missing_required_field_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            EvidenceDigest(algorithm="sha-256")  # type: ignore[call-arg]


class TestEvidenceDigestImmutabilityAndEquality:
    def test_frozen_rejects_attribute_assignment(self) -> None:
        digest = EvidenceDigest(**_VALID_DIGEST)
        with pytest.raises(ValidationError):
            digest.algorithm = "sha3-256"  # type: ignore[misc]

    def test_equality_is_value_based(self) -> None:
        a = EvidenceDigest(**_VALID_DIGEST)
        b = EvidenceDigest(**_VALID_DIGEST)
        assert a == b
        assert a is not b

    def test_hashable(self) -> None:
        a = EvidenceDigest(**_VALID_DIGEST)
        b = EvidenceDigest(**_VALID_DIGEST)
        assert hash(a) == hash(b)
        assert len({a, b}) == 1


# ══════════════════════════════════════════════════════════════════════════
# IdentityEvidenceReference
# ══════════════════════════════════════════════════════════════════════════


class TestIdentityEvidenceReferenceSchemaAlignment:
    def test_required_and_optional_field_names_match_contract(self) -> None:
        document = load_contract("identity-evidence-reference")
        section = require_mapping_field(
            document, "identity_evidence_reference", context="identity-evidence-reference"
        )
        required = set(
            require_sequence_field(section, "required", context="identity_evidence_reference")
        )
        optional = set(
            require_sequence_field(section, "optional", context="identity_evidence_reference")
        )
        model_required = {
            name
            for name, info in IdentityEvidenceReference.model_fields.items()
            if info.is_required()
        }
        model_optional = {
            name
            for name, info in IdentityEvidenceReference.model_fields.items()
            if not info.is_required()
        }
        assert model_required == required
        assert model_optional == optional

    def test_redaction_classification_values_match_closed_vocabulary(self) -> None:
        document = load_contract("identity-evidence-reference")
        section = require_mapping_field(
            document, "identity_evidence_reference", context="identity-evidence-reference"
        )
        values = require_sequence_field(
            section, "redaction_classification_values", context="identity_evidence_reference"
        )
        assert set(values) == {member.value for member in RedactionClassification}


class TestIdentityEvidenceReferenceConstruction:
    def test_minimal_valid_construction(self) -> None:
        ref = IdentityEvidenceReference(
            reference_id="idev-0001-0000-0000-000000000001",
            evidence_digest=_VALID_DIGEST,
            identity_source="oidc:https://idp.example.com",
            redaction_classification=RedactionClassification.REFERENCE_ONLY,
        )
        assert ref.reference_id == "idev-0001-0000-0000-000000000001"
        assert ref.identity_source == "oidc:https://idp.example.com"
        assert ref.redaction_classification == RedactionClassification.REFERENCE_ONLY
        assert ref.normalization_version is None
        assert ref.mapping_version is None
        assert ref.request_id is None
        assert ref.correlation_id is None

    def test_accepts_string_redaction_classification_value(self) -> None:
        ref = IdentityEvidenceReference(
            reference_id="idev-0001-0000-0000-000000000001",
            evidence_digest=_VALID_DIGEST,
            identity_source="basis-local",
            redaction_classification="safe_after_redaction",
        )
        assert ref.redaction_classification == RedactionClassification.SAFE_AFTER_REDACTION

    def test_full_optional_fields_construct(self) -> None:
        ref = IdentityEvidenceReference(
            reference_id="idev-0002-0000-0000-000000000002",
            evidence_digest=_VALID_DIGEST,
            identity_source="oidc:https://idp.example.com",
            redaction_classification=RedactionClassification.REFERENCE_ONLY,
            normalization_version="1.0.0",
            mapping_version="2026-05-01",
            request_id="a1b2c3d4-0001-0000-0000-000000000001",
            correlation_id="corr-0001",
        )
        assert ref.normalization_version == "1.0.0"
        assert ref.mapping_version == "2026-05-01"
        assert ref.request_id == "a1b2c3d4-0001-0000-0000-000000000001"
        assert ref.correlation_id == "corr-0001"

    def test_vendored_valid_examples_construct(self) -> None:
        examples = _valid_examples("identity-evidence-reference", "identity_evidence_reference")
        for example in examples:
            ref = IdentityEvidenceReference(**example)  # type: ignore[arg-type]
            assert ref.reference_id == example["reference_id"]

    def test_vendored_invalid_examples_are_rejected(self) -> None:
        entries = _invalid_examples("identity-evidence-reference", "identity_evidence_reference")
        for entry in entries:
            value = entry["value"]
            assert isinstance(value, dict)
            with pytest.raises(ValidationError):
                IdentityEvidenceReference(**value)

    @pytest.mark.parametrize(
        "field_name",
        ["reference_id", "evidence_digest", "identity_source", "redaction_classification"],
    )
    def test_each_required_field_is_enforced(self, field_name: str) -> None:
        kwargs = {
            "reference_id": "idev-0001-0000-0000-000000000001",
            "evidence_digest": _VALID_DIGEST,
            "identity_source": "oidc:https://idp.example.com",
            "redaction_classification": RedactionClassification.REFERENCE_ONLY,
        }
        del kwargs[field_name]
        with pytest.raises(ValidationError):
            IdentityEvidenceReference(**kwargs)  # type: ignore[arg-type]

    @pytest.mark.parametrize("field_name", ["reference_id", "identity_source"])
    def test_empty_required_string_fields_are_rejected(self, field_name: str) -> None:
        kwargs = {
            "reference_id": "idev-0001-0000-0000-000000000001",
            "evidence_digest": _VALID_DIGEST,
            "identity_source": "oidc:https://idp.example.com",
            "redaction_classification": RedactionClassification.REFERENCE_ONLY,
        }
        kwargs[field_name] = ""
        with pytest.raises(ValidationError):
            IdentityEvidenceReference(**kwargs)  # type: ignore[arg-type]

    def test_empty_request_id_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            IdentityEvidenceReference(
                reference_id="idev-0001-0000-0000-000000000001",
                evidence_digest=_VALID_DIGEST,
                identity_source="oidc:https://idp.example.com",
                redaction_classification=RedactionClassification.REFERENCE_ONLY,
                request_id="",
            )

    def test_unsupported_redaction_classification_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            IdentityEvidenceReference(
                reference_id="idev-0001-0000-0000-000000000001",
                evidence_digest=_VALID_DIGEST,
                identity_source="oidc:https://idp.example.com",
                redaction_classification="public",
            )

    def test_wrong_type_for_evidence_digest_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            IdentityEvidenceReference(
                reference_id="idev-0001-0000-0000-000000000001",
                evidence_digest="not-a-digest-object",  # type: ignore[arg-type]
                identity_source="oidc:https://idp.example.com",
                redaction_classification=RedactionClassification.REFERENCE_ONLY,
            )

    def test_wrong_type_for_reference_id_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            IdentityEvidenceReference(
                reference_id=12345,  # type: ignore[arg-type]
                evidence_digest=_VALID_DIGEST,
                identity_source="oidc:https://idp.example.com",
                redaction_classification=RedactionClassification.REFERENCE_ONLY,
            )


class TestIdentityEvidenceReferenceImmutabilityAndEquality:
    def _make(self, **overrides: object) -> IdentityEvidenceReference:
        kwargs: dict[str, object] = {
            "reference_id": "idev-0001-0000-0000-000000000001",
            "evidence_digest": _VALID_DIGEST,
            "identity_source": "oidc:https://idp.example.com",
            "redaction_classification": RedactionClassification.REFERENCE_ONLY,
        }
        kwargs.update(overrides)
        return IdentityEvidenceReference(**kwargs)  # type: ignore[arg-type]

    def test_frozen_rejects_attribute_assignment(self) -> None:
        ref = self._make()
        with pytest.raises(ValidationError):
            ref.reference_id = "changed"  # type: ignore[misc]

    def test_equality_is_value_based(self) -> None:
        assert self._make() == self._make()

    def test_hashable(self) -> None:
        assert hash(self._make()) == hash(self._make())

    def test_deterministic_repr_round_trips_field_values(self) -> None:
        ref = self._make()
        text = repr(ref)
        assert "IdentityEvidenceReference(" in text
        assert "idev-0001-0000-0000-000000000001" in text


class TestIdentityEvidenceReferenceSecurityAndDataMinimization:
    @pytest.mark.parametrize("field_name", _RAW_EVIDENCE_FIELD_NAMES)
    def test_raw_evidence_fields_are_rejected(self, field_name: str) -> None:
        with pytest.raises(ValidationError):
            IdentityEvidenceReference(
                reference_id="idev-0001-0000-0000-000000000001",
                evidence_digest=_VALID_DIGEST,
                identity_source="oidc:https://idp.example.com",
                redaction_classification=RedactionClassification.REFERENCE_ONLY,
                **{field_name: "inert-placeholder-value"},  # type: ignore[arg-type]
            )

    def test_no_raw_evidence_field_exists_on_the_model_at_all(self) -> None:
        declared_fields = set(IdentityEvidenceReference.model_fields)
        assert declared_fields.isdisjoint(_RAW_EVIDENCE_FIELD_NAMES)

    def test_arbitrary_unknown_field_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            IdentityEvidenceReference(
                reference_id="idev-0001-0000-0000-000000000001",
                evidence_digest=_VALID_DIGEST,
                identity_source="oidc:https://idp.example.com",
                redaction_classification=RedactionClassification.REFERENCE_ONLY,
                confidence=0.97,  # type: ignore[call-arg]
            )


# ══════════════════════════════════════════════════════════════════════════
# AdapterEvidenceReference
# ══════════════════════════════════════════════════════════════════════════


class TestAdapterEvidenceReferenceSchemaAlignment:
    def test_required_and_optional_field_names_match_contract(self) -> None:
        document = load_contract("adapter-evidence-reference")
        section = require_mapping_field(
            document, "adapter_evidence_reference", context="adapter-evidence-reference"
        )
        required = set(
            require_sequence_field(section, "required", context="adapter_evidence_reference")
        )
        optional = set(
            require_sequence_field(section, "optional", context="adapter_evidence_reference")
        )
        model_required = {
            name
            for name, info in AdapterEvidenceReference.model_fields.items()
            if info.is_required()
        }
        model_optional = {
            name
            for name, info in AdapterEvidenceReference.model_fields.items()
            if not info.is_required()
        }
        assert model_required == required
        assert model_optional == optional

    def test_redaction_classification_values_match_closed_vocabulary(self) -> None:
        document = load_contract("adapter-evidence-reference")
        section = require_mapping_field(
            document, "adapter_evidence_reference", context="adapter-evidence-reference"
        )
        values = require_sequence_field(
            section, "redaction_classification_values", context="adapter_evidence_reference"
        )
        assert set(values) == {member.value for member in RedactionClassification}

    def test_protocol_pattern_matches_vendored_contract(self) -> None:
        document = load_contract("adapter-evidence-reference")
        section = require_mapping_field(
            document, "adapter_evidence_reference", context="adapter-evidence-reference"
        )
        fields = require_sequence_field(section, "fields", context="adapter_evidence_reference")
        by_id = {
            require_string_field(f, "id", context="adapter_evidence_reference.field"): f  # type: ignore[arg-type]
            for f in fields
        }
        protocol_pattern = require_string_field(
            by_id["protocol"],
            "pattern",
            context="adapter_evidence_reference.protocol",  # type: ignore[arg-type]
        )
        assert protocol_pattern == r"^[a-z][a-z0-9_-]*$"

        from basis_core.domain.evidence import _PROTOCOL_RE

        assert _PROTOCOL_RE.pattern == protocol_pattern


class TestAdapterEvidenceReferenceConstruction:
    def test_minimal_valid_construction(self) -> None:
        ref = AdapterEvidenceReference(
            reference_id="adev-0001-0000-0000-000000000001",
            evidence_digest=_VALID_DIGEST,
            adapter_source="basis-adapters:modbus",
            redaction_classification=RedactionClassification.REFERENCE_ONLY,
        )
        assert ref.adapter_source == "basis-adapters:modbus"
        assert ref.protocol is None

    def test_full_optional_fields_construct(self) -> None:
        ref = AdapterEvidenceReference(
            reference_id="adev-0001-0000-0000-000000000001",
            evidence_digest=_VALID_DIGEST,
            adapter_source="basis-adapters:modbus",
            redaction_classification=RedactionClassification.REFERENCE_ONLY,
            normalization_version="1.0.0",
            mapping_version="modbus-map-2026-05-01",
            protocol="modbus",
            request_id="a1b2c3d4-0001-0000-0000-000000000001",
            correlation_id="corr-0001",
        )
        assert ref.protocol == "modbus"

    def test_vendored_valid_examples_construct(self) -> None:
        for example in _valid_examples("adapter-evidence-reference", "adapter_evidence_reference"):
            ref = AdapterEvidenceReference(**example)  # type: ignore[arg-type]
            assert ref.reference_id == example["reference_id"]

    def test_vendored_invalid_examples_are_rejected(self) -> None:
        for entry in _invalid_examples("adapter-evidence-reference", "adapter_evidence_reference"):
            value = entry["value"]
            assert isinstance(value, dict)
            with pytest.raises(ValidationError):
                AdapterEvidenceReference(**value)

    @pytest.mark.parametrize(
        "field_name",
        ["reference_id", "evidence_digest", "adapter_source", "redaction_classification"],
    )
    def test_each_required_field_is_enforced(self, field_name: str) -> None:
        kwargs = {
            "reference_id": "adev-0001-0000-0000-000000000001",
            "evidence_digest": _VALID_DIGEST,
            "adapter_source": "basis-adapters:modbus",
            "redaction_classification": RedactionClassification.REFERENCE_ONLY,
        }
        del kwargs[field_name]
        with pytest.raises(ValidationError):
            AdapterEvidenceReference(**kwargs)  # type: ignore[arg-type]

    @pytest.mark.parametrize("field_name", ["reference_id", "adapter_source"])
    def test_empty_required_string_fields_are_rejected(self, field_name: str) -> None:
        kwargs = {
            "reference_id": "adev-0001-0000-0000-000000000001",
            "evidence_digest": _VALID_DIGEST,
            "adapter_source": "basis-adapters:modbus",
            "redaction_classification": RedactionClassification.REFERENCE_ONLY,
        }
        kwargs[field_name] = ""
        with pytest.raises(ValidationError):
            AdapterEvidenceReference(**kwargs)  # type: ignore[arg-type]

    def test_empty_request_id_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AdapterEvidenceReference(
                reference_id="adev-0001-0000-0000-000000000001",
                evidence_digest=_VALID_DIGEST,
                adapter_source="basis-adapters:modbus",
                redaction_classification=RedactionClassification.REFERENCE_ONLY,
                request_id="",
            )

    @pytest.mark.parametrize(
        "protocol,description",
        [
            ("Modbus", "uppercase"),
            ("", "empty"),
            ("modbus tcp", "contains a space"),
        ],
    )
    def test_malformed_protocol_labels_are_rejected(self, protocol: str, description: str) -> None:
        with pytest.raises(ValidationError):
            AdapterEvidenceReference(
                reference_id="adev-0001-0000-0000-000000000001",
                evidence_digest=_VALID_DIGEST,
                adapter_source="basis-adapters:modbus",
                redaction_classification=RedactionClassification.REFERENCE_ONLY,
                protocol=protocol,
            )

    @pytest.mark.parametrize(
        "protocol",
        ["modbus", "bacnet", "opcua", "mqtt", "dnp3", "iec61850", "knx", "niagara", "rest"],
    )
    def test_all_nine_published_adapter_protocol_labels_are_accepted(self, protocol: str) -> None:
        # The model must remain protocol-agnostic: it accepts these purely as
        # opaque labels matching the open pattern, not because it understands
        # any of these nine protocols.
        ref = AdapterEvidenceReference(
            reference_id="adev-0001-0000-0000-000000000001",
            evidence_digest=_VALID_DIGEST,
            adapter_source=f"basis-adapters:{protocol}",
            redaction_classification=RedactionClassification.REFERENCE_ONLY,
            protocol=protocol,
        )
        assert ref.protocol == protocol

    def test_unsupported_redaction_classification_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AdapterEvidenceReference(
                reference_id="adev-0001-0000-0000-000000000001",
                evidence_digest=_VALID_DIGEST,
                adapter_source="basis-adapters:modbus",
                redaction_classification="public",
            )


class TestAdapterEvidenceReferenceImmutabilityAndEquality:
    def _make(self, **overrides: object) -> AdapterEvidenceReference:
        kwargs: dict[str, object] = {
            "reference_id": "adev-0001-0000-0000-000000000001",
            "evidence_digest": _VALID_DIGEST,
            "adapter_source": "basis-adapters:modbus",
            "redaction_classification": RedactionClassification.REFERENCE_ONLY,
        }
        kwargs.update(overrides)
        return AdapterEvidenceReference(**kwargs)  # type: ignore[arg-type]

    def test_frozen_rejects_attribute_assignment(self) -> None:
        ref = self._make()
        with pytest.raises(ValidationError):
            ref.adapter_source = "changed"  # type: ignore[misc]

    def test_equality_is_value_based(self) -> None:
        assert self._make() == self._make()

    def test_hashable(self) -> None:
        assert hash(self._make()) == hash(self._make())

    def test_deterministic_repr_round_trips_field_values(self) -> None:
        ref = self._make()
        text = repr(ref)
        assert "AdapterEvidenceReference(" in text
        assert "adev-0001-0000-0000-000000000001" in text


class TestAdapterEvidenceReferenceSecurityAndDataMinimization:
    @pytest.mark.parametrize("field_name", _RAW_EVIDENCE_FIELD_NAMES)
    def test_raw_evidence_fields_are_rejected(self, field_name: str) -> None:
        with pytest.raises(ValidationError):
            AdapterEvidenceReference(
                reference_id="adev-0001-0000-0000-000000000001",
                evidence_digest=_VALID_DIGEST,
                adapter_source="basis-adapters:modbus",
                redaction_classification=RedactionClassification.REFERENCE_ONLY,
                **{field_name: "inert-placeholder-value"},  # type: ignore[arg-type]
            )

    def test_no_raw_evidence_field_exists_on_the_model_at_all(self) -> None:
        declared_fields = set(AdapterEvidenceReference.model_fields)
        assert declared_fields.isdisjoint(_RAW_EVIDENCE_FIELD_NAMES)

    def test_model_stays_protocol_agnostic_field_set(self) -> None:
        # The model must carry no protocol-specific field (e.g. no BACnet
        # object-id, no Modbus register address) — only the generic,
        # protocol-neutral `protocol` label.
        declared_fields = set(AdapterEvidenceReference.model_fields)
        protocol_specific_terms = {
            "object_id",
            "register_address",
            "node_id",
            "group_address",
            "ord",
            "topic",
        }
        assert declared_fields.isdisjoint(protocol_specific_terms)
