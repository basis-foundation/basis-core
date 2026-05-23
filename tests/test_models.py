"""
Tests for the core authorization contract models.

Covers:
  - Empty ID validation on Subject, Resource, DecisionRequest, DecisionResponse
  - Role normalization (strip whitespace, deduplication, sorting)
  - Action format validation on DecisionRequest
  - Resource ID format validation
  - Timezone-aware timestamp enforcement across all models
  - Allowed and denied decision serialization round-trips
  - AuditEvent decision context correctness
  - subject_from_jwt() contract validation
  - IdentityContext token and timestamp validation
  - Import boundary verification (nothing below api/ imports from api/)
"""

from __future__ import annotations

import ast
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from basis_core.audit.events import AuditEvent, AuditEventType, AuditOutcome
from basis_core.decisions.models import DecisionOutcome, DecisionRequest, DecisionResponse
from basis_core.domain.identity import IdentityContext
from basis_core.domain.resource import Resource, ResourceType, build_resource_id
from basis_core.domain.subject import Subject, SubjectType, subject_from_jwt

# ── Helpers ────────────────────────────────────────────────────────────────────

NOW_UTC = datetime.now(timezone.utc)
NAIVE_DT = datetime(2026, 5, 22, 14, 30, 0)  # no tzinfo — deliberately naive


# ══════════════════════════════════════════════════════════════════════════════
# Subject validation
# ══════════════════════════════════════════════════════════════════════════════


class TestSubjectValidation:
    def test_empty_id_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="must not be empty"):
            Subject(id="", name="alice", roles=[])

    def test_whitespace_only_id_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="must not be empty"):
            Subject(id="   ", name="alice", roles=[])

    def test_empty_name_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="must not be empty"):
            Subject(id="u1", name="", roles=[])

    def test_whitespace_only_name_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="must not be empty"):
            Subject(id="u1", name="\t", roles=[])

    def test_valid_subject_constructs(self) -> None:
        s = Subject(id="u1", name="alice", roles=["operator"])
        assert s.id == "u1"
        assert s.name == "alice"

    def test_roles_are_deduplicated(self) -> None:
        s = Subject(id="u1", name="alice", roles=["operator", "operator", "admin"])
        assert s.roles == ["admin", "operator"]

    def test_roles_are_sorted(self) -> None:
        s = Subject(id="u1", name="alice", roles=["operator", "admin", "viewer"])
        assert s.roles == ["admin", "operator", "viewer"]

    def test_roles_have_whitespace_stripped(self) -> None:
        s = Subject(id="u1", name="alice", roles=["  operator  ", "admin"])
        assert "operator" in s.roles
        assert "admin" in s.roles

    def test_empty_role_strings_are_discarded(self) -> None:
        s = Subject(id="u1", name="alice", roles=["", "  ", "operator"])
        assert s.roles == ["operator"]

    def test_empty_roles_list_is_valid(self) -> None:
        s = Subject(id="u1", name="alice", roles=[])
        assert s.roles == []

    def test_has_role_returns_true_when_held(self) -> None:
        s = Subject(id="u1", name="alice", roles=["operator"])
        assert s.has_role("operator") is True
        assert s.has_role("admin", "operator") is True

    def test_has_role_returns_false_when_not_held(self) -> None:
        s = Subject(id="u1", name="alice", roles=["viewer"])
        assert s.has_role("operator") is False

    def test_subject_is_frozen(self) -> None:
        s = Subject(id="u1", name="alice", roles=[])
        with pytest.raises(Exception):
            s.id = "u2"  # type: ignore[misc]

    def test_str_representation(self) -> None:
        s = Subject(id="u1", name="alice", type=SubjectType.HUMAN, roles=[])
        assert str(s) == "human:alice"


# ══════════════════════════════════════════════════════════════════════════════
# subject_from_jwt
# ══════════════════════════════════════════════════════════════════════════════


class TestSubjectFromJwt:
    def test_valid_jwt_payload_constructs_subject(self) -> None:
        payload = {
            "sub": "a7b8c9d0-1234-5678-abcd-ef0123456789",
            "preferred_username": "alice",
            "realm_access": {"roles": ["operator"]},
            "email": "alice@example.com",
        }
        s = subject_from_jwt(payload)
        assert s.id == "a7b8c9d0-1234-5678-abcd-ef0123456789"
        assert s.name == "alice"
        assert s.type == SubjectType.HUMAN
        assert "operator" in s.roles

    def test_missing_sub_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="sub"):
            subject_from_jwt({"preferred_username": "alice"})

    def test_empty_sub_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="sub"):
            subject_from_jwt({"sub": "", "preferred_username": "alice"})

    def test_missing_username_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="preferred_username"):
            subject_from_jwt({"sub": "abc-123"})

    def test_email_stored_in_attrs(self) -> None:
        payload = {
            "sub": "u1",
            "preferred_username": "alice",
            "email": "alice@example.com",
        }
        s = subject_from_jwt(payload)
        assert s.attrs.get("email") == "alice@example.com"

    def test_roles_normalized_from_jwt(self) -> None:
        payload = {
            "sub": "u1",
            "preferred_username": "alice",
            "realm_access": {"roles": ["operator", "operator", "admin"]},
        }
        s = subject_from_jwt(payload)
        assert s.roles == ["admin", "operator"]


# ══════════════════════════════════════════════════════════════════════════════
# Resource validation
# ══════════════════════════════════════════════════════════════════════════════


class TestResourceValidation:
    def test_valid_resource_constructs(self) -> None:
        r = Resource(id="hvac:zone-a", type=ResourceType.HVAC, name="zone-a")
        assert r.id == "hvac:zone-a"

    def test_empty_id_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="empty"):
            Resource(id="", type=ResourceType.HVAC, name="zone-a")

    def test_id_without_colon_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="format"):
            Resource(id="hvac-zone-a", type=ResourceType.HVAC, name="zone-a")

    def test_empty_name_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="empty"):
            Resource(id="hvac:zone-a", type=ResourceType.HVAC, name="")

    def test_build_resource_id(self) -> None:
        assert build_resource_id(ResourceType.HVAC, "zone-a") == "hvac:zone-a"
        assert build_resource_id(ResourceType.SENSOR, "co2", "lobby") == "sensor:co2:lobby"

    def test_build_resource_id_requires_qualifier(self) -> None:
        with pytest.raises(ValueError):
            build_resource_id(ResourceType.HVAC)

    def test_resource_is_frozen(self) -> None:
        r = Resource(id="hvac:zone-a", type=ResourceType.HVAC, name="zone-a")
        with pytest.raises(Exception):
            r.id = "sensor:co2"  # type: ignore[misc]


# ══════════════════════════════════════════════════════════════════════════════
# IdentityContext validation
# ══════════════════════════════════════════════════════════════════════════════


class TestIdentityContextValidation:
    def _make_subject(self) -> Subject:
        return Subject(id="u1", name="alice", roles=["operator"])

    def test_valid_context_constructs(self) -> None:
        ctx = IdentityContext(
            subject=self._make_subject(),
            token="a.b.c",
            issued_at=NOW_UTC,
        )
        assert ctx.token == "a.b.c"

    def test_empty_token_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="empty"):
            IdentityContext(
                subject=self._make_subject(),
                token="",
                issued_at=NOW_UTC,
            )

    def test_whitespace_only_token_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="empty"):
            IdentityContext(
                subject=self._make_subject(),
                token="   ",
                issued_at=NOW_UTC,
            )

    def test_naive_issued_at_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="timezone-aware"):
            IdentityContext(
                subject=self._make_subject(),
                token="a.b.c",
                issued_at=NAIVE_DT,
            )

    def test_naive_expires_at_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="timezone-aware"):
            IdentityContext(
                subject=self._make_subject(),
                token="a.b.c",
                issued_at=NOW_UTC,
                expires_at=NAIVE_DT,
            )

    def test_is_expired_returns_false_when_no_expiry(self) -> None:
        ctx = IdentityContext(
            subject=self._make_subject(),
            token="a.b.c",
            issued_at=NOW_UTC,
        )
        assert ctx.is_expired() is False

    def test_is_expired_returns_true_when_past_expiry(self) -> None:
        past = datetime(2020, 1, 1, tzinfo=timezone.utc)
        ctx = IdentityContext(
            subject=self._make_subject(),
            token="a.b.c",
            issued_at=past,
            expires_at=past,
        )
        assert ctx.is_expired() is True


# ══════════════════════════════════════════════════════════════════════════════
# DecisionRequest validation
# ══════════════════════════════════════════════════════════════════════════════


class TestDecisionRequestValidation:
    def test_valid_request_constructs(self) -> None:
        req = DecisionRequest(
            subject_id="u1",
            action="write:hvac:setpoint",
            resource_id="hvac:zone-a",
        )
        assert req.subject_id == "u1"

    def test_empty_subject_id_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="empty"):
            DecisionRequest(subject_id="", action="write:hvac:setpoint")

    def test_whitespace_subject_id_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="empty"):
            DecisionRequest(subject_id="  ", action="write:hvac:setpoint")

    def test_empty_action_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="empty"):
            DecisionRequest(subject_id="u1", action="")

    def test_action_without_colon_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="format"):
            DecisionRequest(subject_id="u1", action="writesetpoint")

    def test_action_with_uppercase_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="format"):
            DecisionRequest(subject_id="u1", action="Write:HVAC:Setpoint")

    def test_valid_action_format_accepted(self) -> None:
        req = DecisionRequest(subject_id="u1", action="write:hvac:setpoint")
        assert req.action == "write:hvac:setpoint"

    def test_roles_normalized_on_request(self) -> None:
        req = DecisionRequest(
            subject_id="u1",
            action="write:hvac:setpoint",
            subject_roles=["operator", "operator", "  admin  "],
        )
        assert req.subject_roles == ["admin", "operator"]

    def test_naive_timestamp_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="timezone-aware"):
            DecisionRequest(
                subject_id="u1",
                action="write:hvac:setpoint",
                timestamp=NAIVE_DT,
            )

    def test_default_timestamp_is_tz_aware(self) -> None:
        req = DecisionRequest(subject_id="u1", action="write:hvac:setpoint")
        assert req.timestamp.tzinfo is not None

    def test_request_id_auto_generated(self) -> None:
        req = DecisionRequest(subject_id="u1", action="write:hvac:setpoint")
        assert len(req.request_id) > 0

    def test_two_requests_have_different_ids(self) -> None:
        r1 = DecisionRequest(subject_id="u1", action="write:hvac:setpoint")
        r2 = DecisionRequest(subject_id="u1", action="write:hvac:setpoint")
        assert r1.request_id != r2.request_id


# ══════════════════════════════════════════════════════════════════════════════
# DecisionResponse validation
# ══════════════════════════════════════════════════════════════════════════════


class TestDecisionResponseValidation:
    def test_valid_allow_response_constructs(self) -> None:
        resp = DecisionResponse(
            request_id="req-1",
            outcome=DecisionOutcome.ALLOW,
            reason="Permitted by RolePolicy.",
            evaluated_by="RolePolicy",
        )
        assert resp.allowed is True
        assert resp.outcome == DecisionOutcome.ALLOW

    def test_valid_deny_response_constructs(self) -> None:
        resp = DecisionResponse(
            request_id="req-1",
            outcome=DecisionOutcome.DENY,
            reason="Insufficient roles.",
            evaluated_by="RolePolicy",
        )
        assert resp.allowed is False

    def test_empty_request_id_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="empty"):
            DecisionResponse(
                request_id="",
                outcome=DecisionOutcome.ALLOW,
                reason="ok",
                evaluated_by="TestPolicy",
            )

    def test_empty_reason_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="empty"):
            DecisionResponse(
                request_id="req-1",
                outcome=DecisionOutcome.DENY,
                reason="",
                evaluated_by="TestPolicy",
            )

    def test_empty_evaluated_by_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="empty"):
            DecisionResponse(
                request_id="req-1",
                outcome=DecisionOutcome.DENY,
                reason="Denied.",
                evaluated_by="",
            )

    def test_naive_timestamp_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="timezone-aware"):
            DecisionResponse(
                request_id="req-1",
                outcome=DecisionOutcome.ALLOW,
                reason="ok",
                evaluated_by="TestPolicy",
                timestamp=NAIVE_DT,
            )

    def test_default_timestamp_is_tz_aware(self) -> None:
        resp = DecisionResponse(
            request_id="req-1",
            outcome=DecisionOutcome.ALLOW,
            reason="ok",
            evaluated_by="TestPolicy",
        )
        assert resp.timestamp.tzinfo is not None

    def test_allow_serializes_correctly(self) -> None:
        resp = DecisionResponse(
            request_id="req-1",
            outcome=DecisionOutcome.ALLOW,
            reason="Permitted.",
            evaluated_by="RolePolicy",
        )
        data = resp.model_dump(mode="json")
        assert data["outcome"] == "allow"
        assert data["request_id"] == "req-1"
        assert data["reason"] == "Permitted."

    def test_deny_serializes_correctly(self) -> None:
        resp = DecisionResponse(
            request_id="req-2",
            outcome=DecisionOutcome.DENY,
            reason="Denied.",
            evaluated_by="RolePolicy",
        )
        data = resp.model_dump(mode="json")
        assert data["outcome"] == "deny"

    def test_serialized_response_round_trips(self) -> None:
        resp = DecisionResponse(
            request_id="req-1",
            outcome=DecisionOutcome.ALLOW,
            reason="Permitted.",
            evaluated_by="RolePolicy",
            policy_version="v1",
        )
        data = json.dumps(resp.model_dump(mode="json"))
        reloaded = DecisionResponse.model_validate_json(data)
        assert reloaded.outcome == resp.outcome
        assert reloaded.request_id == resp.request_id
        assert reloaded.policy_version == resp.policy_version


# ══════════════════════════════════════════════════════════════════════════════
# AuditEvent validation
# ══════════════════════════════════════════════════════════════════════════════


class TestAuditEventValidation:
    def test_minimal_audit_event_constructs(self) -> None:
        ev = AuditEvent(action="write:hvac:setpoint")
        assert ev.event_id
        assert ev.timestamp.tzinfo is not None
        assert ev.event_type == AuditEventType.AUTHORIZATION_DECISION

    def test_empty_action_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="empty"):
            AuditEvent(action="")

    def test_empty_event_id_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="empty"):
            AuditEvent(event_id="", action="write:hvac:setpoint")

    def test_naive_timestamp_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="timezone-aware"):
            AuditEvent(action="write:hvac:setpoint", timestamp=NAIVE_DT)

    def test_allow_event_carries_full_decision_context(self) -> None:
        ev = AuditEvent(
            event_type=AuditEventType.AUTHORIZATION_DECISION,
            subject_id="u1",
            subject_name="alice",
            subject_type="human",
            subject_roles=["operator"],
            action="write:hvac:setpoint",
            resource_id="hvac:zone-a",
            resource_type="hvac",
            outcome=AuditOutcome.ALLOWED,
            reason="Subject holds a role permitted for 'write:hvac:setpoint'.",
            evaluated_by="RolePolicy",
            policy_version="v1.0.0",
            request_id="req-1",
        )
        assert ev.subject_id == "u1"
        assert ev.outcome == AuditOutcome.ALLOWED
        assert ev.resource_id == "hvac:zone-a"
        assert ev.policy_version == "v1.0.0"
        assert ev.request_id == "req-1"

    def test_deny_event_carries_full_decision_context(self) -> None:
        ev = AuditEvent(
            subject_id="u2",
            subject_name="bob",
            subject_type="human",
            subject_roles=["viewer"],
            action="write:hvac:setpoint",
            resource_id="hvac:zone-a",
            resource_type="hvac",
            outcome=AuditOutcome.DENIED,
            reason="Insufficient roles.",
            evaluated_by="RolePolicy",
            request_id="req-2",
        )
        assert ev.outcome == AuditOutcome.DENIED
        assert ev.subject_name == "bob"

    def test_audit_event_serializes_to_json(self) -> None:
        ev = AuditEvent(
            action="write:hvac:setpoint",
            outcome=AuditOutcome.ALLOWED,
        )
        data = ev.model_dump(mode="json")
        assert data["action"] == "write:hvac:setpoint"
        assert data["outcome"] == "allowed"
        assert "Z" in data["timestamp"] or "+" in data["timestamp"]

    def test_audit_event_round_trips(self) -> None:
        ev = AuditEvent(
            subject_id="u1",
            action="read:audit:log",
            outcome=AuditOutcome.ALLOWED,
            evaluated_by="RolePolicy",
        )
        data = json.dumps(ev.model_dump(mode="json"))
        reloaded = AuditEvent.model_validate_json(data)
        assert reloaded.event_id == ev.event_id
        assert reloaded.outcome == ev.outcome


# ══════════════════════════════════════════════════════════════════════════════
# Import boundary verification
# ══════════════════════════════════════════════════════════════════════════════


class TestImportBoundaries:
    """
    Verify statically that no subpackage below api/ imports from basis_core.api.

    Uses ast.parse() to inspect source files without executing them, so this
    test does not depend on import order or module loading state.
    """

    SRC_ROOT = Path(__file__).parent.parent / "src" / "basis_core"

    # Subpackages that must not import from basis_core.api
    RESTRICTED_PACKAGES = ["domain", "policy", "decisions", "audit", "adapters"]

    def _collect_imports(self, path: Path) -> list[str]:
        """Return all imported module names found in a Python source file."""
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        imports: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.append(node.module)
        return imports

    def test_domain_does_not_import_from_api(self) -> None:
        pkg_dir = self.SRC_ROOT / "domain"
        for py_file in pkg_dir.glob("*.py"):
            imports = self._collect_imports(py_file)
            for imp in imports:
                assert not imp.startswith("basis_core.api"), (
                    f"{py_file.name}: domain/ must not import from basis_core.api, found '{imp}'"
                )

    def test_policy_does_not_import_from_api(self) -> None:
        pkg_dir = self.SRC_ROOT / "policy"
        for py_file in pkg_dir.glob("*.py"):
            imports = self._collect_imports(py_file)
            for imp in imports:
                assert not imp.startswith("basis_core.api"), (
                    f"{py_file.name}: policy/ must not import from basis_core.api, found '{imp}'"
                )

    def test_decisions_does_not_import_from_api(self) -> None:
        pkg_dir = self.SRC_ROOT / "decisions"
        for py_file in pkg_dir.glob("*.py"):
            imports = self._collect_imports(py_file)
            for imp in imports:
                assert not imp.startswith("basis_core.api"), (
                    f"{py_file.name}: decisions/ must not import from basis_core.api, found '{imp}'"
                )

    def test_audit_does_not_import_from_api(self) -> None:
        pkg_dir = self.SRC_ROOT / "audit"
        for py_file in pkg_dir.glob("*.py"):
            imports = self._collect_imports(py_file)
            for imp in imports:
                assert not imp.startswith("basis_core.api"), (
                    f"{py_file.name}: audit/ must not import from basis_core.api, found '{imp}'"
                )

    def test_adapters_does_not_import_from_api(self) -> None:
        pkg_dir = self.SRC_ROOT / "adapters"
        for py_file in pkg_dir.glob("*.py"):
            imports = self._collect_imports(py_file)
            for imp in imports:
                assert not imp.startswith("basis_core.api"), (
                    f"{py_file.name}: adapters/ must not import from basis_core.api, found '{imp}'"
                )

    def test_policy_does_not_import_from_decisions(self) -> None:
        """policy/ must not import decisions/ — it reasons about domain types only."""
        pkg_dir = self.SRC_ROOT / "policy"
        for py_file in pkg_dir.glob("*.py"):
            imports = self._collect_imports(py_file)
            for imp in imports:
                assert not imp.startswith("basis_core.decisions"), (
                    f"{py_file.name}: policy/ must not import from basis_core.decisions, "
                    f"found '{imp}'"
                )

    def test_domain_has_no_basis_core_imports(self) -> None:
        """domain/ must have zero imports from any basis_core subpackage."""
        pkg_dir = self.SRC_ROOT / "domain"
        for py_file in pkg_dir.glob("*.py"):
            imports = self._collect_imports(py_file)
            for imp in imports:
                # identity.py imports basis_core.domain.subject — same package, allowed
                if imp.startswith("basis_core.") and not imp.startswith("basis_core.domain"):
                    pytest.fail(
                        f"{py_file.name}: domain/ must not import from other "
                        f"basis_core subpackages, found '{imp}'"
                    )
