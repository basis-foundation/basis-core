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
        assert _all_of("basis_core.domain") == DOMAIN_PUBLIC, (
            "basis_core.domain.__all__ does not match the documented inventory. "
            "Update __all__ in src/basis_core/domain/__init__.py and "
            "docs/public-api.md together."
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
        assert _all_of("basis_core.decisions") == DECISIONS_PUBLIC

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
        assert _all_of("basis_core.policy") == POLICY_PUBLIC

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
        assert _all_of("basis_core.audit") == AUDIT_PUBLIC

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
        assert _all_of("basis_core.enforcement") == ENFORCEMENT_PUBLIC

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


# ── Deprecated basis_core.api ─────────────────────────────────────────────────


class TestDeprecatedApiPackage:
    """
    basis_core.api is a deprecated stub. It must not be treated as public API.
    EnforcementPoint is re-exported there for backward compatibility only.
    """

    def test_api_package_still_importable(self) -> None:
        """The stub must remain importable to avoid breaking existing imports."""
        import basis_core.api  # noqa: F401

    def test_api_enforcement_stub_importable(self) -> None:
        from basis_core.api.enforcement import EnforcementPoint  # noqa: F401

    def test_enforcement_point_identity(self) -> None:
        """The stub must re-export the same class, not a copy."""
        from basis_core.api.enforcement import EnforcementPoint as ApiEP
        from basis_core.enforcement import EnforcementPoint as CoreEP

        assert ApiEP is CoreEP, (
            "basis_core.api.enforcement.EnforcementPoint is not the same object "
            "as basis_core.enforcement.EnforcementPoint. The stub must re-export "
            "the canonical class, not wrap it."
        )
