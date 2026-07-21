"""
tests/test_public_api.py — public API surface contract tests.

These tests protect the importability and export inventory of the public API
declared in ``docs/public-api.md``. They verify three guarantees:

  1. Every declared public symbol is importable from its stated import path.
  2. Each package's ``__all__`` list exactly matches the documented inventory.
  3. Internal symbols (those starting with ``_``) are not re-exported by any
     package ``__init__.py``.

What these tests do NOT check:
- Internal behaviour or implementation details.
- The serialised shapes of models (covered by test_contract_snapshots.py).
- The evaluation algorithm (covered by test_evaluation_semantics.py).
- Extension interface behavioural contracts (covered by test_extension_contracts.py).

If a test here fails it means either:
  (a) a public symbol was accidentally removed or renamed  — fix the code, or
  (b) a new public symbol was added without updating the inventory — update
      docs/public-api.md, the package __all__, and the snapshot sets below.
"""

from __future__ import annotations

import importlib
import types

# ── Canonical inventory ────────────────────────────────────────────────────────
# Each set is the single source of truth for what ``__all__`` must contain in the
# corresponding package. Changes here are a documented, reviewable public API
# change; do not update these sets without also updating docs/public-api.md.

DOMAIN_PUBLIC: frozenset[str] = frozenset(
    {
        "Subject",
        "SubjectType",
        "subject_from_jwt",
        "Resource",
        "ResourceType",
        "build_resource_id",
        "parse_resource_id",
        "IdentityContext",
        "action",
    }
)

DECISIONS_PUBLIC: frozenset[str] = frozenset(
    {
        "DecisionRequest",
        "DecisionResponse",
        "DecisionOutcome",
        "FailureReason",
    }
)

POLICY_PUBLIC: frozenset[str] = frozenset(
    {
        "PolicyEngine",
        "PolicyRule",
        "Decision",
        "PolicyOutcome",
        "RolePolicyRule",
        "ResourceTypePolicyRule",
        "ActionPolicyRule",
    }
)

AUDIT_PUBLIC: frozenset[str] = frozenset(
    {
        "AuditEvent",
        "AuditEventType",
        "AuditOutcome",
        "AUDIT_SCHEMA_VERSION",
        "AuditWriter",
        "NullAuditWriter",
        "LogAuditWriter",
        "DecisionTrace",
        "RuleEvaluation",
    }
)

ENFORCEMENT_PUBLIC: frozenset[str] = frozenset({"EnforcementPoint"})

ADAPTERS_PUBLIC: frozenset[str] = frozenset({"AdapterBase", "NormalizedEvent"})


# ── Operation-aware (v0.2.0) canonical inventory ───────────────────────────────
# Additive to the v0.1 sets above. Each package's __all__ must equal the union
# of its v0.1 set and its operation-aware set below — the v0.1 set itself is
# never modified by this section. See docs/public-api.md's "Operation-aware
# public API (v0.2.0)" section, which this inventory must stay in lockstep with.

DOMAIN_OA_PUBLIC: frozenset[str] = frozenset(
    {
        "RedactionClassification",
        "ReasonCode",
        "EvidenceDigest",
        "IdentityEvidenceReference",
        "AdapterEvidenceReference",
        "OperationAwareLocation",
        "OperationAwareDevice",
        "OperationAwareProtocolContext",
        "OperationAwareSafetyContext",
        "OperationAwareEnvironmentContext",
        "OperationAwareRiskContext",
    }
)

DECISIONS_OA_PUBLIC: frozenset[str] = frozenset(
    {
        "OperationAwareDecisionRequest",
        "OperationIntent",
        "OperationAwareFailureReason",
        "OperationAwareEvaluationStatus",
        "OperationAwareDecisionOutcome",
    }
)

POLICY_OA_PUBLIC: frozenset[str] = frozenset(
    {
        "PolicyCondition",
        "OperationAwarePolicyRule",
        "OperationAwarePolicyMatch",
        "RuleEffect",
        "PolicyBundle",
        "PolicyBundleScope",
    }
)

AUDIT_OA_PUBLIC: frozenset[str] = frozenset(
    {
        "TraceRuleEvidence",
        "TraceConditionEvidence",
        "TraceRuleEffect",
        "RuleResult",
        "TraceConditionResult",
        "EvaluationTrace",
        "EvaluationStatus",
        "TraceOutcome",
        "TraceBundleApplicability",
        "TraceFailureReason",
        "AuditEvidence",
        "AUDIT_EVIDENCE_SCHEMA_VERSION",
    }
)

ENFORCEMENT_OA_PUBLIC: frozenset[str] = frozenset(
    {
        "EnforcementDisposition",
        "OperationAwareEnforcementPoint",
        "OperationAwareEnforcementResult",
    }
)

# Internal operation-aware implementation symbols that must NOT appear in any
# package's __all__. Representative names drawn from every internal
# evaluator/selector/operator/aggregation/validation/assembly/orchestration
# module touched by the v0.2.0 roadmap (Section 11).
INTERNAL_OPERATION_AWARE_SYMBOLS: frozenset[str] = frozenset(
    {
        # evaluation-orchestration (excluded from this PR entirely)
        "OperationAwareEvaluationEngine",
        "OperationAwareDecisionResponse",
        "assemble_operation_aware_decision_response",
        "assemble_audit_evidence",
        "assemble_evaluation_trace",
        "assemble_rule_evidence",
        # policy-owned internal orchestration/evaluation/validation
        "determine_applicability",
        "ApplicabilityResult",
        "select_candidate_rules",
        "evaluate_rule_selectors",
        "SelectorEvaluation",
        "SelectorMatchResult",
        "CandidateRuleEvaluation",
        "evaluate_rule_conditions",
        "ConditionEvaluation",
        "ConditionResult",
        "RuleConditionEvaluation",
        "RuleConditionResult",
        "aggregate_policy_results",
        "aggregate_policy_outcome",
        "OperationAwarePolicyOutcome",
        "PolicyAggregationResult",
        "PolicyAggregationStatus",
        "PolicyAggregationInputError",
        "EvaluatedRule",
        "validate_policy_bundle",
        "PolicyBundleValidationError",
        "StructuralPolicyValidationError",
        "SemanticPolicyValidationError",
        "DuplicateRuleIdError",
        "DuplicateConditionIdError",
    }
)


# ── Helpers ────────────────────────────────────────────────────────────────────


def _import(dotted: str) -> object:
    """Import a dotted name and return the object at the leaf."""
    module_path, _, attr = dotted.rpartition(".")
    if module_path:
        mod = importlib.import_module(module_path)
        return getattr(mod, attr)
    return importlib.import_module(dotted)


def _all_of(package: str) -> frozenset[str]:
    """Return the ``__all__`` of a package as a frozenset."""
    mod = importlib.import_module(package)
    return frozenset(getattr(mod, "__all__", []))


def _exported_internals(package: str) -> list[str]:
    """Return any names in ``__all__`` that start with ``_``."""
    return [name for name in _all_of(package) if name.startswith("_")]


# ── basis_core.domain ──────────────────────────────────────────────────────────


class TestDomainPackage:
    """basis_core.domain public API surface."""

    def test_all_matches_inventory(self) -> None:
        assert _all_of("basis_core.domain") == DOMAIN_PUBLIC | DOMAIN_OA_PUBLIC, (
            "basis_core.domain.__all__ does not match the documented inventory "
            "(v0.1 DOMAIN_PUBLIC union operation-aware DOMAIN_OA_PUBLIC). "
            "Update __all__ in src/basis_core/domain/__init__.py and "
            "docs/public-api.md together."
        )

    def test_v01_inventory_unchanged(self) -> None:
        """The v0.1 DOMAIN_PUBLIC set itself is never modified by this PR."""
        assert DOMAIN_PUBLIC == frozenset(
            {
                "Subject",
                "SubjectType",
                "subject_from_jwt",
                "Resource",
                "ResourceType",
                "build_resource_id",
                "parse_resource_id",
                "IdentityContext",
                "action",
            }
        )

    def test_no_internal_exports(self) -> None:
        leaked = _exported_internals("basis_core.domain")
        assert not leaked, f"Internal symbols exported by basis_core.domain: {leaked}"

    def test_subject_importable_from_package(self) -> None:
        from basis_core.domain import Subject  # noqa: F401

        assert Subject is not None

    def test_subject_type_importable_from_package(self) -> None:
        from basis_core.domain import SubjectType  # noqa: F401

        assert SubjectType is not None

    def test_subject_from_jwt_importable_from_package(self) -> None:
        from basis_core.domain import subject_from_jwt  # noqa: F401

        assert callable(subject_from_jwt)

    def test_resource_importable_from_package(self) -> None:
        from basis_core.domain import Resource  # noqa: F401

        assert Resource is not None

    def test_resource_type_importable_from_package(self) -> None:
        from basis_core.domain import ResourceType  # noqa: F401

        assert ResourceType is not None

    def test_build_resource_id_importable_from_package(self) -> None:
        from basis_core.domain import build_resource_id  # noqa: F401

        assert callable(build_resource_id)

    def test_parse_resource_id_importable_from_package(self) -> None:
        from basis_core.domain import parse_resource_id  # noqa: F401

        assert callable(parse_resource_id)

    def test_identity_context_importable_from_package(self) -> None:
        from basis_core.domain import IdentityContext  # noqa: F401

        assert IdentityContext is not None

    def test_action_module_importable_from_package(self) -> None:
        from basis_core.domain import action  # noqa: F401

        assert isinstance(action, types.ModuleType)

    def test_action_module_has_expected_constants(self) -> None:
        from basis_core.domain import action

        expected = {
            "READ_SENSOR_TELEMETRY",
            "SUBSCRIBE_TELEMETRY",
            "DISCONNECT_TELEMETRY",
            "READ_HVAC_STATE",
            "WRITE_HVAC_SETPOINT",
            "WRITE_HVAC_MODE",
            "READ_DEVICE_STATE",
            "WRITE_DEVICE_SETPOINT",
            "EXECUTE_DEVICE_COMMAND",
            "READ_ZONE_STATE",
            "READ_RESOURCES",
            "READ_AUDIT_LOG",
            "READ_POLICY",
            "WRITE_POLICY",
        }
        for name in expected:
            assert hasattr(action, name), f"action.{name} is missing"
            assert isinstance(getattr(action, name), str), f"action.{name} must be a str"

    def test_symbols_also_importable_from_submodules(self) -> None:
        """Submodule import paths must also work (both paths are public)."""
        from basis_core.domain.identity import IdentityContext  # noqa: F401
        from basis_core.domain.resource import (  # noqa: F401  # noqa: F401
            Resource,
            ResourceType,
            build_resource_id,
            parse_resource_id,
        )
        from basis_core.domain.subject import Subject, SubjectType, subject_from_jwt  # noqa: F401


# ── basis_core.decisions ───────────────────────────────────────────────────────


class TestDecisionsPackage:
    """basis_core.decisions public API surface."""

    def test_all_matches_inventory(self) -> None:
        assert _all_of("basis_core.decisions") == DECISIONS_PUBLIC | DECISIONS_OA_PUBLIC

    def test_v01_inventory_unchanged(self) -> None:
        assert DECISIONS_PUBLIC == frozenset(
            {"DecisionRequest", "DecisionResponse", "DecisionOutcome", "FailureReason"}
        )

    def test_no_internal_exports(self) -> None:
        assert not _exported_internals("basis_core.decisions")

    def test_decision_request_importable(self) -> None:
        from basis_core.decisions import DecisionRequest  # noqa: F401

    def test_decision_response_importable(self) -> None:
        from basis_core.decisions import DecisionResponse  # noqa: F401

    def test_decision_outcome_importable(self) -> None:
        from basis_core.decisions import DecisionOutcome  # noqa: F401

    def test_failure_reason_importable(self) -> None:
        from basis_core.decisions import FailureReason  # noqa: F401

    def test_symbols_also_importable_from_submodule(self) -> None:
        from basis_core.decisions.models import (  # noqa: F401
            DecisionOutcome,
            DecisionRequest,
            DecisionResponse,
            FailureReason,
        )

    def test_internal_regexes_not_exported(self) -> None:
        import basis_core.decisions as pkg

        all_names = frozenset(_all_of("basis_core.decisions"))
        assert "_ACTION_RE" not in all_names
        assert "_RESOURCE_ID_RE" not in all_names
        # The objects must still exist in the submodule (needed internally).
        import basis_core.decisions.models as m

        assert hasattr(m, "_ACTION_RE")
        assert hasattr(m, "_RESOURCE_ID_RE")
        # But they must NOT be listed in the package __all__.
        _ = pkg  # suppress unused-import warning


# ── basis_core.policy ─────────────────────────────────────────────────────────


class TestPolicyPackage:
    """basis_core.policy public API surface."""

    def test_all_matches_inventory(self) -> None:
        assert _all_of("basis_core.policy") == POLICY_PUBLIC | POLICY_OA_PUBLIC

    def test_v01_inventory_unchanged(self) -> None:
        assert POLICY_PUBLIC == frozenset(
            {
                "PolicyEngine",
                "PolicyRule",
                "Decision",
                "PolicyOutcome",
                "RolePolicyRule",
                "ResourceTypePolicyRule",
                "ActionPolicyRule",
            }
        )

    def test_policy_rule_is_still_v01_protocol(self) -> None:
        """The naming-collision guard required by PR 35: `PolicyRule` must
        remain the v0.1.0 extension-point Protocol, never the operation-aware
        `OperationAwarePolicyRule` data model."""
        from basis_core.policy import OperationAwarePolicyRule, PolicyRule
        from basis_core.policy.engine import PolicyRule as ConcretePolicyRule

        assert PolicyRule is ConcretePolicyRule
        assert PolicyRule is not OperationAwarePolicyRule

    def test_no_internal_exports(self) -> None:
        assert not _exported_internals("basis_core.policy")

    def test_policy_engine_importable(self) -> None:
        from basis_core.policy import PolicyEngine  # noqa: F401

    def test_policy_rule_importable(self) -> None:
        from basis_core.policy import PolicyRule  # noqa: F401

    def test_decision_importable(self) -> None:
        from basis_core.policy import Decision  # noqa: F401

    def test_policy_outcome_importable(self) -> None:
        from basis_core.policy import PolicyOutcome  # noqa: F401

    def test_role_policy_rule_importable(self) -> None:
        from basis_core.policy import RolePolicyRule  # noqa: F401

    def test_resource_type_policy_rule_importable(self) -> None:
        from basis_core.policy import ResourceTypePolicyRule  # noqa: F401

    def test_action_policy_rule_importable(self) -> None:
        from basis_core.policy import ActionPolicyRule  # noqa: F401

    def test_symbols_also_importable_from_submodules(self) -> None:
        from basis_core.policy.engine import (  # noqa: F401  # noqa: F401
            Decision,
            PolicyEngine,
            PolicyOutcome,
            PolicyRule,
        )
        from basis_core.policy.rules import (  # noqa: F401
            ActionPolicyRule,  # noqa: F401
            ResourceTypePolicyRule,
            RolePolicyRule,
        )


# ── basis_core.audit ──────────────────────────────────────────────────────────


class TestAuditPackage:
    """basis_core.audit public API surface."""

    def test_all_matches_inventory(self) -> None:
        assert _all_of("basis_core.audit") == AUDIT_PUBLIC | AUDIT_OA_PUBLIC

    def test_v01_inventory_unchanged(self) -> None:
        assert AUDIT_PUBLIC == frozenset(
            {
                "AuditEvent",
                "AuditEventType",
                "AuditOutcome",
                "AUDIT_SCHEMA_VERSION",
                "AuditWriter",
                "NullAuditWriter",
                "LogAuditWriter",
                "DecisionTrace",
                "RuleEvaluation",
            }
        )

    def test_no_internal_exports(self) -> None:
        assert not _exported_internals("basis_core.audit")

    def test_audit_event_importable(self) -> None:
        from basis_core.audit import AuditEvent  # noqa: F401

    def test_audit_event_type_importable(self) -> None:
        from basis_core.audit import AuditEventType  # noqa: F401

    def test_audit_outcome_importable(self) -> None:
        from basis_core.audit import AuditOutcome  # noqa: F401

    def test_audit_schema_version_importable(self) -> None:
        from basis_core.audit import AUDIT_SCHEMA_VERSION

        assert isinstance(AUDIT_SCHEMA_VERSION, str)
        assert AUDIT_SCHEMA_VERSION  # non-empty

    def test_audit_writer_importable(self) -> None:
        from basis_core.audit import AuditWriter  # noqa: F401

    def test_null_audit_writer_importable(self) -> None:
        from basis_core.audit import NullAuditWriter  # noqa: F401

    def test_log_audit_writer_importable(self) -> None:
        from basis_core.audit import LogAuditWriter  # noqa: F401

    def test_decision_trace_importable(self) -> None:
        from basis_core.audit import DecisionTrace  # noqa: F401

    def test_rule_evaluation_importable(self) -> None:
        from basis_core.audit import RuleEvaluation  # noqa: F401

    def test_symbols_also_importable_from_submodules(self) -> None:
        from basis_core.audit.events import (  # noqa: F401
            AUDIT_SCHEMA_VERSION,  # noqa: F401
            AuditEvent,
            AuditEventType,
            AuditOutcome,
        )
        from basis_core.audit.trace import DecisionTrace, RuleEvaluation  # noqa: F401
        from basis_core.audit.writer import (  # noqa: F401
            AuditWriter,
            LogAuditWriter,
            NullAuditWriter,  # noqa: F401
        )

    def test_log_object_not_exported(self) -> None:
        """The module-level ``log`` logger must not appear in __all__."""
        assert "log" not in _all_of("basis_core.audit")


# ── basis_core.enforcement ────────────────────────────────────────────────────


class TestEnforcementPackage:
    """basis_core.enforcement public API surface."""

    def test_all_matches_inventory(self) -> None:
        assert _all_of("basis_core.enforcement") == ENFORCEMENT_PUBLIC | ENFORCEMENT_OA_PUBLIC

    def test_v01_inventory_unchanged(self) -> None:
        assert ENFORCEMENT_PUBLIC == frozenset({"EnforcementPoint"})

    def test_no_internal_exports(self) -> None:
        assert not _exported_internals("basis_core.enforcement")

    def test_enforcement_point_importable(self) -> None:
        from basis_core.enforcement import EnforcementPoint  # noqa: F401

    def test_enforcement_point_also_importable_from_submodule(self) -> None:
        from basis_core.enforcement.enforcement import EnforcementPoint  # noqa: F401

    def test_internal_constants_not_exported(self) -> None:
        """Private module-level constants must not appear in __all__."""
        exported = _all_of("basis_core.enforcement")
        internal_names = {
            "_POLICY_OUTCOME_TO_DECISION_OUTCOME",
            "_DECISION_OUTCOME_TO_AUDIT_OUTCOME",
            "_REASON_MALFORMED",
            "_REASON_POLICY_ERROR",
            "_REASON_INTERNAL",
            "log",
        }
        leaked = internal_names & exported
        assert not leaked, f"Internal symbols in basis_core.enforcement.__all__: {leaked}"

    def test_write_audit_is_private(self) -> None:
        """_write_audit is a private method; it must not appear in __all__."""
        assert "_write_audit" not in _all_of("basis_core.enforcement")

    def test_enforcement_point_has_evaluate(self) -> None:
        from basis_core.enforcement import EnforcementPoint

        assert callable(getattr(EnforcementPoint, "evaluate", None))

    def test_enforcement_point_has_policy_version_property(self) -> None:
        """policy_version must be a public read-only property on EnforcementPoint."""
        from basis_core.enforcement import EnforcementPoint

        assert isinstance(
            EnforcementPoint.__dict__.get("policy_version"),
            property,
        ), "EnforcementPoint.policy_version must be a property, not a plain attribute"


# ── basis_core.adapters ───────────────────────────────────────────────────────


class TestAdaptersPackage:
    """basis_core.adapters public API surface."""

    def test_all_matches_inventory(self) -> None:
        assert _all_of("basis_core.adapters") == ADAPTERS_PUBLIC

    def test_no_internal_exports(self) -> None:
        assert not _exported_internals("basis_core.adapters")

    def test_adapter_base_importable(self) -> None:
        from basis_core.adapters import AdapterBase  # noqa: F401

    def test_normalized_event_importable(self) -> None:
        from basis_core.adapters import NormalizedEvent  # noqa: F401

    def test_symbols_also_importable_from_submodule(self) -> None:
        from basis_core.adapters.base import AdapterBase, NormalizedEvent  # noqa: F401


# ── basis_core operation-aware (v0.2.0) public API ─────────────────────────────
# PR 35: additive-only. Every check here is in addition to, never a
# replacement for, the v0.1 checks above.


class TestDomainOperationAwareExports:
    """basis_core.domain operation-aware (v0.2.0) export coverage."""

    def test_each_symbol_appears_exactly_once(self) -> None:
        all_list = list(_all_of("basis_core.domain"))
        for name in DOMAIN_OA_PUBLIC:
            assert all_list.count(name) == 1, f"{name} must appear exactly once in __all__"

    def test_each_symbol_is_package_attribute(self) -> None:
        import basis_core.domain as pkg

        for name in DOMAIN_OA_PUBLIC:
            assert hasattr(pkg, name), f"basis_core.domain.{name} is missing"

    def test_each_symbol_identical_to_concrete_object(self) -> None:
        import basis_core.domain as pkg
        import basis_core.domain.evidence as evidence
        import basis_core.domain.operation_aware as operation_aware
        import basis_core.domain.operation_aware_vocabulary as vocab

        concrete = {
            "RedactionClassification": vocab.RedactionClassification,
            "ReasonCode": vocab.ReasonCode,
            "EvidenceDigest": evidence.EvidenceDigest,
            "IdentityEvidenceReference": evidence.IdentityEvidenceReference,
            "AdapterEvidenceReference": evidence.AdapterEvidenceReference,
            "OperationAwareLocation": operation_aware.OperationAwareLocation,
            "OperationAwareDevice": operation_aware.OperationAwareDevice,
            "OperationAwareProtocolContext": operation_aware.OperationAwareProtocolContext,
            "OperationAwareSafetyContext": operation_aware.OperationAwareSafetyContext,
            "OperationAwareEnvironmentContext": operation_aware.OperationAwareEnvironmentContext,
            "OperationAwareRiskContext": operation_aware.OperationAwareRiskContext,
        }
        assert concrete.keys() == DOMAIN_OA_PUBLIC
        for name, obj in concrete.items():
            assert getattr(pkg, name) is obj, f"basis_core.domain.{name} is not the concrete object"

    def test_documented_imports_succeed(self) -> None:
        from basis_core.domain import (  # noqa: F401
            AdapterEvidenceReference,
            EvidenceDigest,
            IdentityEvidenceReference,
            OperationAwareDevice,
            OperationAwareEnvironmentContext,
            OperationAwareLocation,
            OperationAwareProtocolContext,
            OperationAwareRiskContext,
            OperationAwareSafetyContext,
            ReasonCode,
            RedactionClassification,
        )

    def test_no_collision_with_v01_names(self) -> None:
        assert not (DOMAIN_OA_PUBLIC & DOMAIN_PUBLIC)

    def test_not_exported_from_unrelated_packages(self) -> None:
        for other in ("basis_core.decisions", "basis_core.policy", "basis_core.audit"):
            leaked = DOMAIN_OA_PUBLIC & _all_of(other)
            assert not leaked, f"domain operation-aware symbols leaked into {other}: {leaked}"


class TestDecisionsOperationAwareExports:
    """basis_core.decisions operation-aware (v0.2.0) export coverage."""

    def test_each_symbol_appears_exactly_once(self) -> None:
        all_list = list(_all_of("basis_core.decisions"))
        for name in DECISIONS_OA_PUBLIC:
            assert all_list.count(name) == 1

    def test_each_symbol_is_package_attribute(self) -> None:
        import basis_core.decisions as pkg

        for name in DECISIONS_OA_PUBLIC:
            assert hasattr(pkg, name), f"basis_core.decisions.{name} is missing"

    def test_each_symbol_identical_to_concrete_object(self) -> None:
        import basis_core.decisions as pkg
        import basis_core.decisions.operation_aware as oa

        concrete = {
            "OperationAwareDecisionRequest": oa.OperationAwareDecisionRequest,
            "OperationIntent": oa.OperationIntent,
            "OperationAwareFailureReason": oa.OperationAwareFailureReason,
            "OperationAwareEvaluationStatus": oa.OperationAwareEvaluationStatus,
            "OperationAwareDecisionOutcome": oa.OperationAwareDecisionOutcome,
        }
        assert concrete.keys() == DECISIONS_OA_PUBLIC
        for name, obj in concrete.items():
            assert getattr(pkg, name) is obj

    def test_documented_imports_succeed(self) -> None:
        from basis_core.decisions import (  # noqa: F401
            OperationAwareDecisionOutcome,
            OperationAwareDecisionRequest,
            OperationAwareEvaluationStatus,
            OperationAwareFailureReason,
            OperationIntent,
        )

    def test_no_collision_with_v01_names(self) -> None:
        assert not (DECISIONS_OA_PUBLIC & DECISIONS_PUBLIC)

    def test_not_exported_from_unrelated_packages(self) -> None:
        for other in ("basis_core.domain", "basis_core.policy", "basis_core.audit"):
            leaked = DECISIONS_OA_PUBLIC & _all_of(other)
            assert not leaked, f"decisions operation-aware symbols leaked into {other}: {leaked}"


class TestPolicyOperationAwareExports:
    """basis_core.policy operation-aware (v0.2.0) export coverage."""

    def test_each_symbol_appears_exactly_once(self) -> None:
        all_list = list(_all_of("basis_core.policy"))
        for name in POLICY_OA_PUBLIC:
            assert all_list.count(name) == 1

    def test_each_symbol_is_package_attribute(self) -> None:
        import basis_core.policy as pkg

        for name in POLICY_OA_PUBLIC:
            assert hasattr(pkg, name), f"basis_core.policy.{name} is missing"

    def test_each_symbol_identical_to_concrete_object(self) -> None:
        import basis_core.policy as pkg
        import basis_core.policy.operation_aware.bundle as bundle
        import basis_core.policy.operation_aware.condition as condition
        import basis_core.policy.operation_aware.rule as rule

        concrete = {
            "PolicyCondition": condition.PolicyCondition,
            "OperationAwarePolicyRule": rule.OperationAwarePolicyRule,
            "OperationAwarePolicyMatch": rule.OperationAwarePolicyMatch,
            "RuleEffect": rule.RuleEffect,
            "PolicyBundle": bundle.PolicyBundle,
            "PolicyBundleScope": bundle.PolicyBundleScope,
        }
        assert concrete.keys() == POLICY_OA_PUBLIC
        for name, obj in concrete.items():
            assert getattr(pkg, name) is obj

    def test_documented_imports_succeed(self) -> None:
        from basis_core.policy import (  # noqa: F401
            OperationAwarePolicyMatch,
            OperationAwarePolicyRule,
            PolicyBundle,
            PolicyBundleScope,
            PolicyCondition,
            RuleEffect,
        )

    def test_no_collision_with_v01_names(self) -> None:
        assert not (POLICY_OA_PUBLIC & POLICY_PUBLIC)

    def test_not_exported_from_unrelated_packages(self) -> None:
        for other in ("basis_core.domain", "basis_core.decisions", "basis_core.audit"):
            leaked = POLICY_OA_PUBLIC & _all_of(other)
            assert not leaked, f"policy operation-aware symbols leaked into {other}: {leaked}"

    def test_internal_policy_symbols_not_exported(self) -> None:
        leaked = INTERNAL_OPERATION_AWARE_SYMBOLS & _all_of("basis_core.policy")
        assert not leaked, f"internal policy symbols leaked into basis_core.policy: {leaked}"


class TestAuditOperationAwareExports:
    """basis_core.audit operation-aware (v0.2.0) export coverage."""

    def test_each_symbol_appears_exactly_once(self) -> None:
        all_list = list(_all_of("basis_core.audit"))
        for name in AUDIT_OA_PUBLIC:
            assert all_list.count(name) == 1

    def test_each_symbol_is_package_attribute(self) -> None:
        import basis_core.audit as pkg

        for name in AUDIT_OA_PUBLIC:
            assert hasattr(pkg, name), f"basis_core.audit.{name} is missing"

    def test_each_symbol_identical_to_concrete_object(self) -> None:
        import basis_core.audit as pkg
        import basis_core.audit.operation_aware.audit_evidence as audit_evidence
        import basis_core.audit.operation_aware.evaluation_trace as evaluation_trace
        import basis_core.audit.operation_aware.trace_rule_evidence as trace_rule_evidence

        concrete = {
            "TraceRuleEvidence": trace_rule_evidence.TraceRuleEvidence,
            "TraceConditionEvidence": trace_rule_evidence.TraceConditionEvidence,
            "TraceRuleEffect": trace_rule_evidence.TraceRuleEffect,
            "RuleResult": trace_rule_evidence.RuleResult,
            "TraceConditionResult": trace_rule_evidence.TraceConditionResult,
            "EvaluationTrace": evaluation_trace.EvaluationTrace,
            "EvaluationStatus": evaluation_trace.EvaluationStatus,
            "TraceOutcome": evaluation_trace.TraceOutcome,
            "TraceBundleApplicability": evaluation_trace.TraceBundleApplicability,
            "TraceFailureReason": evaluation_trace.TraceFailureReason,
            "AuditEvidence": audit_evidence.AuditEvidence,
            "AUDIT_EVIDENCE_SCHEMA_VERSION": audit_evidence.AUDIT_EVIDENCE_SCHEMA_VERSION,
        }
        assert concrete.keys() == AUDIT_OA_PUBLIC
        for name, obj in concrete.items():
            assert getattr(pkg, name) is obj

    def test_documented_imports_succeed(self) -> None:
        from basis_core.audit import (  # noqa: F401
            AUDIT_EVIDENCE_SCHEMA_VERSION,
            AuditEvidence,
            EvaluationStatus,
            EvaluationTrace,
            RuleResult,
            TraceBundleApplicability,
            TraceConditionEvidence,
            TraceConditionResult,
            TraceFailureReason,
            TraceOutcome,
            TraceRuleEffect,
            TraceRuleEvidence,
        )

    def test_no_collision_with_v01_names(self) -> None:
        assert not (AUDIT_OA_PUBLIC & AUDIT_PUBLIC)

    def test_not_exported_from_unrelated_packages(self) -> None:
        for other in ("basis_core.domain", "basis_core.decisions", "basis_core.policy"):
            leaked = AUDIT_OA_PUBLIC & _all_of(other)
            assert not leaked, f"audit operation-aware symbols leaked into {other}: {leaked}"


class TestEnforcementOperationAwareExports:
    """basis_core.enforcement operation-aware (v0.2.0) export coverage."""

    def test_each_symbol_appears_exactly_once(self) -> None:
        all_list = list(_all_of("basis_core.enforcement"))
        for name in ENFORCEMENT_OA_PUBLIC:
            assert all_list.count(name) == 1

    def test_each_symbol_is_package_attribute(self) -> None:
        import basis_core.enforcement as pkg

        for name in ENFORCEMENT_OA_PUBLIC:
            assert hasattr(pkg, name), f"basis_core.enforcement.{name} is missing"

    def test_each_symbol_identical_to_concrete_object(self) -> None:
        import basis_core.enforcement as pkg
        import basis_core.enforcement.operation_aware as oa

        concrete = {
            "EnforcementDisposition": oa.EnforcementDisposition,
            "OperationAwareEnforcementPoint": oa.OperationAwareEnforcementPoint,
            "OperationAwareEnforcementResult": oa.OperationAwareEnforcementResult,
        }
        assert concrete.keys() == ENFORCEMENT_OA_PUBLIC
        for name, obj in concrete.items():
            assert getattr(pkg, name) is obj

    def test_documented_imports_succeed(self) -> None:
        from basis_core.enforcement import (  # noqa: F401
            EnforcementDisposition,
            OperationAwareEnforcementPoint,
            OperationAwareEnforcementResult,
        )

    def test_no_collision_with_v01_names(self) -> None:
        assert not (ENFORCEMENT_OA_PUBLIC & ENFORCEMENT_PUBLIC)

    def test_enforcement_point_still_v01_unchanged_sibling(self) -> None:
        """ADR-0006: OperationAwareEnforcementPoint does not modify, subclass,
        or share implementation with EnforcementPoint."""
        from basis_core.enforcement import EnforcementPoint, OperationAwareEnforcementPoint

        assert OperationAwareEnforcementPoint is not EnforcementPoint
        assert not issubclass(OperationAwareEnforcementPoint, EnforcementPoint)
        assert not issubclass(EnforcementPoint, OperationAwareEnforcementPoint)

    def test_not_exported_from_unrelated_packages(self) -> None:
        for other in (
            "basis_core.domain",
            "basis_core.decisions",
            "basis_core.policy",
            "basis_core.audit",
        ):
            leaked = ENFORCEMENT_OA_PUBLIC & _all_of(other)
            assert not leaked, f"enforcement operation-aware symbols leaked into {other}: {leaked}"


class TestInternalOperationAwareRestraint:
    """No internal operation-aware implementation symbol is exported at the
    package level, across every touched package."""

    def test_no_internal_symbol_in_any_touched_package(self) -> None:
        for package in (
            "basis_core.domain",
            "basis_core.decisions",
            "basis_core.policy",
            "basis_core.audit",
            "basis_core.enforcement",
        ):
            leaked = INTERNAL_OPERATION_AWARE_SYMBOLS & _all_of(package)
            assert not leaked, f"internal operation-aware symbols leaked into {package}: {leaked}"

    def test_internal_symbols_still_importable_from_concrete_modules(self) -> None:
        """'Internal' means 'not part of the approved package-level API', not
        'unimportable' — direct submodule imports of these symbols must still
        work."""
        from basis_core.evaluation.operation_aware.response import (  # noqa: F401
            OperationAwareDecisionResponse,
        )
        from basis_core.policy.operation_aware.aggregation import (  # noqa: F401
            OperationAwarePolicyOutcome,
            aggregate_policy_outcome,
        )
        from basis_core.policy.operation_aware.applicability import (  # noqa: F401
            ApplicabilityResult,
            determine_applicability,
        )
        from basis_core.policy.operation_aware.validation import (  # noqa: F401
            PolicyBundleValidationError,
            validate_policy_bundle,
        )


class TestEvaluationPackageRemainsInternal:
    """The evaluation-orchestration package is deliberately excluded from
    PR 35 — it gains no __all__, no package-level export, and no
    docs/public-api.md entry."""

    def test_evaluation_package_has_no_all(self) -> None:
        import basis_core.evaluation as evaluation

        assert not hasattr(evaluation, "__all__"), (
            "basis_core.evaluation now declares __all__. This is an "
            "evaluation-layer public API change explicitly out of scope for "
            "PR 35 — see docs/implementation/basis-core-v0.2-operation-aware-"
            "plan.md, PR 35's non-goals."
        )

    def test_evaluation_operation_aware_package_has_no_all(self) -> None:
        import basis_core.evaluation.operation_aware as oa_evaluation

        assert not hasattr(oa_evaluation, "__all__")

    def test_evaluation_response_type_not_reexported_by_enforcement(self) -> None:
        """OperationAwareDecisionResponse may be returned inside
        OperationAwareEnforcementResult.response, but it must not gain a new
        package-level import path through `enforcement`, `audit`, or
        `decisions`."""
        for package in ("basis_core.enforcement", "basis_core.audit", "basis_core.decisions"):
            assert "OperationAwareDecisionResponse" not in _all_of(package)
            assert "OperationAwareEvaluationEngine" not in _all_of(package)


class TestOperationAwareDocumentationAgreement:
    """docs/public-api.md's operation-aware inventory must match the
    package-level __all__ inventory exactly (small explicit expected
    inventory, matching this repository's existing convention — no Markdown
    parser)."""

    def test_public_api_doc_mentions_every_approved_symbol(self) -> None:
        import pathlib

        doc_path = pathlib.Path(__file__).resolve().parent.parent / "docs" / "public-api.md"
        text = doc_path.read_text(encoding="utf-8")
        all_oa_symbols = (
            DOMAIN_OA_PUBLIC
            | DECISIONS_OA_PUBLIC
            | POLICY_OA_PUBLIC
            | AUDIT_OA_PUBLIC
            | ENFORCEMENT_OA_PUBLIC
        )
        missing = [name for name in all_oa_symbols if f"`{name}`" not in text]
        assert not missing, f"docs/public-api.md is missing a mention of: {missing}"

    def test_public_api_doc_has_operation_aware_section(self) -> None:
        import pathlib

        doc_path = pathlib.Path(__file__).resolve().parent.parent / "docs" / "public-api.md"
        text = doc_path.read_text(encoding="utf-8")
        assert "## Operation-aware public API (v0.2.0)" in text

    def test_internal_symbols_not_mentioned_as_public_in_new_section(self) -> None:
        """A representative sample of internal names must not appear inside
        the operation-aware section's own text as if they were exported
        symbols with an import path."""
        import pathlib

        doc_path = pathlib.Path(__file__).resolve().parent.parent / "docs" / "public-api.md"
        text = doc_path.read_text(encoding="utf-8")
        section_start = text.index("## Operation-aware public API (v0.2.0)")
        section_end = text.index("## Internal symbols")
        section_text = text[section_start:section_end]
        for name in (
            "OperationAwareEvaluationEngine",
            "assemble_operation_aware_decision_response",
            "assemble_audit_evidence",
            "determine_applicability",
            "aggregate_policy_outcome",
            "validate_policy_bundle",
        ):
            # These names may appear in prose (e.g. explaining what stays
            # internal) but must never appear inside a `Symbol` table cell
            # backtick-quoted exactly like an approved export.
            assert f"| `{name}` |" not in section_text, (
                f"{name} appears formatted as an approved-export table row "
                "in the operation-aware public-api.md section"
            )


# ── basis_core (top-level package) ───────────────────────────────────────────


class TestTopLevelPackage:
    """
    The top-level basis_core package intentionally exports nothing.

    If a convenience top-level namespace is ever added, update this test and
    docs/public-api.md together. The open question is tracked as
    OPEN: top-level-namespace in docs/public-api.md.
    """

    def test_top_level_has_no_all(self) -> None:
        """basis_core.__init__ declares no __all__ (no top-level re-exports)."""
        import basis_core

        assert not hasattr(basis_core, "__all__"), (
            "basis_core.__init__.py now declares __all__. "
            "Update this test and docs/public-api.md to document the "
            "new top-level namespace."
        )

    def test_top_level_importable(self) -> None:
        import basis_core  # noqa: F401

        assert basis_core is not None

    def test_no_operation_aware_symbol_leaks_to_top_level(self) -> None:
        """PR 35 does not modify src/basis_core/__init__.py; no operation-aware
        symbol gains a new `basis_core.<Symbol>` top-level import path."""
        import basis_core

        all_oa_symbols = (
            DOMAIN_OA_PUBLIC
            | DECISIONS_OA_PUBLIC
            | POLICY_OA_PUBLIC
            | AUDIT_OA_PUBLIC
            | ENFORCEMENT_OA_PUBLIC
        )
        for name in all_oa_symbols:
            assert not hasattr(basis_core, name), (
                f"basis_core.{name} unexpectedly resolves — top-level namespace restraint violated"
            )
