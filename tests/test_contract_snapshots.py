"""
tests/test_contract_snapshots.py — contract snapshot tests for basis-core public models.

These tests protect the serialized shape of the four public kernel model types:
DecisionRequest, DecisionResponse, AuditEvent, and DecisionTrace. They catch
field renames, field removals, type changes, and any structural drift that would
break consumers relying on the stable serialization contract.

Each test constructs a model instance with fully deterministic values, serializes
it, and compares the result against a stored JSON fixture in
tests/fixtures/contracts/. If the serialized shape differs from the fixture, the
test fails with a field-level diff.

How to update a fixture deliberately
─────────────────────────────────────
If you have made an intentional, reviewed additive change (new optional field,
new enum value) and need to update a fixture:

    1. Run the test to see the field diff.
    2. If the change is additive and reviewed, update the fixture file manually.
    3. Commit the fixture change alongside the model change so the diff is visible
       in code review.

Breaking changes (field removal, rename, type change, required field addition)
require architecture review per docs/schema-versioning.md before fixture update.

Cross-references
────────────────
docs/compatibility-testing.md — overview of the full harness.
docs/schema-versioning.md     — breaking vs. additive change definitions.
docs/kernel-constitution.md   — Invariant 9: compatibility is a public contract.
"""

from __future__ import annotations

from datetime import datetime, timezone

from basis_core.audit.events import AuditEvent, AuditEventType, AuditOutcome
from basis_core.audit.trace import DecisionTrace, RuleEvaluation
from basis_core.decisions.models import (
    DecisionOutcome,
    DecisionRequest,
    DecisionResponse,
)
from tests.helpers.contracts import assert_matches_fixture, fixture_names

# ---------------------------------------------------------------------------
# Fixed values — kept in sync with tests/fixtures/contracts/
# ---------------------------------------------------------------------------

_TS = datetime(2026, 5, 22, 14, 30, 0, tzinfo=timezone.utc)

_ALLOW_REQUEST_ID = "a1b2c3d4-0001-0000-0000-000000000001"
_DENY_REQUEST_ID = "a1b2c3d4-0002-0000-0000-000000000002"
_SUBJECT_ID = "a7b8c9d0-1234-5678-abcd-ef0123456789"
_ALLOW_EVENT_ID = "e1000000-0000-0000-0000-000000000001"
_DENY_EVENT_ID = "e1000000-0000-0000-0000-000000000002"

# ---------------------------------------------------------------------------
# Shared model builders
# ---------------------------------------------------------------------------


def _allow_trace() -> DecisionTrace:
    return DecisionTrace(
        final_outcome="allow",
        evaluated_rules=[
            RuleEvaluation(
                rule_name="RolePolicyRule",
                outcome="allow",
                reason="Role 'operator' is permitted for 'write:hvac:setpoint'.",
            ),
            RuleEvaluation(
                rule_name="ResourceTypePolicyRule",
                outcome="not_applicable",
                reason="No resource type restrictions for this action.",
            ),
        ],
        short_circuited=False,
    )


def _deny_trace() -> DecisionTrace:
    return DecisionTrace(
        final_outcome="deny",
        evaluated_rules=[
            RuleEvaluation(
                rule_name="RolePolicyRule",
                outcome="deny",
                reason="Role 'viewer' is not permitted to perform 'write:hvac:setpoint'.",
            ),
        ],
        short_circuited=True,
    )


# ---------------------------------------------------------------------------
# DecisionRequest snapshots
# ---------------------------------------------------------------------------


class TestDecisionRequestSnapshots:
    """Serialization shape of DecisionRequest must match stored fixtures."""

    def test_allow_request_matches_fixture(self) -> None:
        """allow scenario: operator role, resource present, full field set."""
        req = DecisionRequest(
            request_id=_ALLOW_REQUEST_ID,
            subject_id=_SUBJECT_ID,
            subject_roles=["operator"],
            subject_attrs={},
            resource_id="hvac:zone-a",
            action="write:hvac:setpoint",
            context={},
            timestamp=_TS,
        )
        assert_matches_fixture(req, "decision_request.allow")

    def test_deny_request_matches_fixture(self) -> None:
        """deny scenario: viewer role, same resource and action."""
        req = DecisionRequest(
            request_id=_DENY_REQUEST_ID,
            subject_id=_SUBJECT_ID,
            subject_roles=["viewer"],
            subject_attrs={},
            resource_id="hvac:zone-a",
            action="write:hvac:setpoint",
            context={},
            timestamp=_TS,
        )
        assert_matches_fixture(req, "decision_request.deny")

    def test_all_expected_fields_present(self) -> None:
        """Every required and optional field in the contract is present."""
        from tests.helpers.contracts import load_fixture

        fixture = load_fixture("decision_request.allow")
        expected_fields = {
            "request_id",
            "subject_id",
            "subject_roles",
            "subject_attrs",
            "resource_id",
            "action",
            "context",
            "timestamp",
        }
        assert set(fixture.keys()) == expected_fields, (
            f"Fixture field set has changed. "
            f"Extra: {set(fixture.keys()) - expected_fields}, "
            f"Missing: {expected_fields - set(fixture.keys())}"
        )

    def test_subject_roles_normalization_preserved(self) -> None:
        """Roles are sorted and deduplicated; fixture reflects normalized order."""
        from tests.helpers.contracts import load_fixture

        fixture = load_fixture("decision_request.allow")
        roles = fixture["subject_roles"]
        assert roles == sorted(roles), "Fixture subject_roles are not in sorted order."
        assert len(roles) == len(set(roles)), "Fixture subject_roles contains duplicates."


# ---------------------------------------------------------------------------
# DecisionResponse snapshots
# ---------------------------------------------------------------------------


class TestDecisionResponseSnapshots:
    """Serialization shape of DecisionResponse must match stored fixtures."""

    def test_allow_response_matches_fixture(self) -> None:
        """allow outcome: outcome='allow', no failure_reason."""
        resp = DecisionResponse(
            request_id=_ALLOW_REQUEST_ID,
            outcome=DecisionOutcome.ALLOW,
            reason="Subject holds a role permitted for 'write:hvac:setpoint'.",
            evaluated_by="RolePolicyRule",
            policy_version="v1.0.0",
            failure_reason=None,
            timestamp=_TS,
        )
        assert_matches_fixture(resp, "decision_response.allow")

    def test_deny_response_matches_fixture(self) -> None:
        """deny outcome: outcome='deny', no failure_reason (policy produced the denial)."""
        resp = DecisionResponse(
            request_id=_DENY_REQUEST_ID,
            outcome=DecisionOutcome.DENY,
            reason="Subject role 'viewer' is not permitted to perform 'write:hvac:setpoint'.",
            evaluated_by="RolePolicyRule",
            policy_version="v1.0.0",
            failure_reason=None,
            timestamp=_TS,
        )
        assert_matches_fixture(resp, "decision_response.deny")

    def test_all_expected_fields_present(self) -> None:
        """Every field in the response contract is present."""
        from tests.helpers.contracts import load_fixture

        fixture = load_fixture("decision_response.allow")
        expected_fields = {
            "request_id",
            "outcome",
            "reason",
            "evaluated_by",
            "policy_version",
            "failure_reason",
            "timestamp",
        }
        assert set(fixture.keys()) == expected_fields, (
            f"Fixture field set has changed. "
            f"Extra: {set(fixture.keys()) - expected_fields}, "
            f"Missing: {expected_fields - set(fixture.keys())}"
        )

    def test_outcome_values_are_strings(self) -> None:
        """Serialized outcome is a plain string, not an enum wrapper."""
        from tests.helpers.contracts import load_fixture

        fixture = load_fixture("decision_response.allow")
        assert isinstance(fixture["outcome"], str), (
            "outcome must serialize as a plain string, not an enum or object"
        )
        assert fixture["outcome"] == "allow"


# ---------------------------------------------------------------------------
# AuditEvent snapshots
# ---------------------------------------------------------------------------


class TestAuditEventSnapshots:
    """Serialization shape of AuditEvent must match stored fixtures."""

    def test_allow_event_matches_fixture(self) -> None:
        """allowed outcome: includes trace with allow + not_applicable rule."""
        event = AuditEvent(
            event_id=_ALLOW_EVENT_ID,
            event_type=AuditEventType.AUTHORIZATION_DECISION,
            timestamp=_TS,
            schema_version="1.1",
            request_id=_ALLOW_REQUEST_ID,
            decision_id=None,
            correlation_id=None,
            subject_id=_SUBJECT_ID,
            subject_name=None,
            subject_type="human",
            subject_roles=["operator"],
            action="write:hvac:setpoint",
            resource_id="hvac:zone-a",
            resource_type="hvac",
            outcome=AuditOutcome.ALLOWED,
            reason="Subject holds a role permitted for 'write:hvac:setpoint'.",
            evaluated_by="RolePolicyRule",
            policy_version="v1.0.0",
            matched_rules=["RolePolicyRule"],
            trace=_allow_trace(),
            detail={},
        )
        assert_matches_fixture(event, "audit_event.allow")

    def test_deny_event_matches_fixture(self) -> None:
        """denied outcome: includes short-circuited trace with single deny rule."""
        event = AuditEvent(
            event_id=_DENY_EVENT_ID,
            event_type=AuditEventType.AUTHORIZATION_DECISION,
            timestamp=_TS,
            schema_version="1.1",
            request_id=_DENY_REQUEST_ID,
            decision_id=None,
            correlation_id=None,
            subject_id=_SUBJECT_ID,
            subject_name=None,
            subject_type="human",
            subject_roles=["viewer"],
            action="write:hvac:setpoint",
            resource_id="hvac:zone-a",
            resource_type="hvac",
            outcome=AuditOutcome.DENIED,
            reason="Subject role 'viewer' is not permitted to perform 'write:hvac:setpoint'.",
            evaluated_by="RolePolicyRule",
            policy_version="v1.0.0",
            matched_rules=["RolePolicyRule"],
            trace=_deny_trace(),
            detail={},
        )
        assert_matches_fixture(event, "audit_event.deny")

    def test_schema_version_in_fixture(self) -> None:
        """schema_version must be present and equal to '1.1' in stored fixture."""
        from tests.helpers.contracts import load_fixture

        fixture = load_fixture("audit_event.allow")
        assert "schema_version" in fixture, "schema_version field missing from audit_event fixture"
        assert fixture["schema_version"] == "1.1", (
            f"schema_version changed: expected '1.1', got {fixture['schema_version']!r}. "
            "Updating schema_version is a breaking change for audit record consumers."
        )

    def test_all_expected_fields_present(self) -> None:
        """Every field in the AuditEvent contract is present in the fixture."""
        from tests.helpers.contracts import load_fixture

        fixture = load_fixture("audit_event.allow")
        expected_fields = {
            "event_id",
            "event_type",
            "timestamp",
            "schema_version",
            "request_id",
            "decision_id",
            "correlation_id",
            "subject_id",
            "subject_name",
            "subject_type",
            "subject_roles",
            "action",
            "resource_id",
            "resource_type",
            "outcome",
            "reason",
            "evaluated_by",
            "policy_version",
            "matched_rules",
            "trace",
            "detail",
        }
        assert set(fixture.keys()) == expected_fields, (
            f"Fixture field set has changed. "
            f"Extra: {set(fixture.keys()) - expected_fields}, "
            f"Missing: {expected_fields - set(fixture.keys())}"
        )

    def test_trace_shape_in_allow_fixture(self) -> None:
        """Trace in allow fixture has two rules: one allow, one not_applicable."""
        from tests.helpers.contracts import load_fixture

        fixture = load_fixture("audit_event.allow")
        trace = fixture["trace"]
        assert trace["final_outcome"] == "allow"
        assert trace["short_circuited"] is False
        assert len(trace["evaluated_rules"]) == 2
        outcomes = [r["outcome"] for r in trace["evaluated_rules"]]
        assert outcomes == ["allow", "not_applicable"]

    def test_trace_shape_in_deny_fixture(self) -> None:
        """Trace in deny fixture has one rule (short-circuited on deny)."""
        from tests.helpers.contracts import load_fixture

        fixture = load_fixture("audit_event.deny")
        trace = fixture["trace"]
        assert trace["final_outcome"] == "deny"
        assert trace["short_circuited"] is True
        assert len(trace["evaluated_rules"]) == 1
        assert trace["evaluated_rules"][0]["outcome"] == "deny"


# ---------------------------------------------------------------------------
# DecisionTrace snapshots
# ---------------------------------------------------------------------------


class TestDecisionTraceSnapshots:
    """Serialization shape of DecisionTrace must match stored fixtures."""

    def test_allow_trace_matches_fixture(self) -> None:
        """allow trace: two rules, ALLOW does not short-circuit."""
        trace = _allow_trace()
        assert_matches_fixture(trace, "evaluation_trace.allow")

    def test_deny_trace_matches_fixture(self) -> None:
        """deny trace: one rule, DENY short-circuits immediately."""
        trace = _deny_trace()
        assert_matches_fixture(trace, "evaluation_trace.deny")

    def test_allow_trace_short_circuited_false(self) -> None:
        """ALLOW outcome — short_circuited must be False in stored fixture."""
        from tests.helpers.contracts import load_fixture

        fixture = load_fixture("evaluation_trace.allow")
        assert fixture["short_circuited"] is False, (
            "short_circuited must be False for ALLOW outcomes (ALLOW does not short-circuit)."
        )

    def test_deny_trace_short_circuited_true(self) -> None:
        """DENY outcome — short_circuited must be True when not all rules were evaluated."""
        from tests.helpers.contracts import load_fixture

        fixture = load_fixture("evaluation_trace.deny")
        assert fixture["short_circuited"] is True, (
            "short_circuited must be True for short-circuit DENY outcomes."
        )

    def test_evaluated_rules_order_preserved(self) -> None:
        """Rule order in fixture matches registration order (first evaluated is first)."""
        from tests.helpers.contracts import load_fixture

        fixture = load_fixture("evaluation_trace.allow")
        names = [r["rule_name"] for r in fixture["evaluated_rules"]]
        assert names == ["RolePolicyRule", "ResourceTypePolicyRule"], (
            f"Rule order in fixture has changed: {names}. "
            "Rule order is a contract (first ALLOW wins for evaluated_by)."
        )

    def test_rule_evaluation_fields_complete(self) -> None:
        """Each rule entry has exactly rule_name, outcome, and reason."""
        from tests.helpers.contracts import load_fixture

        expected_fields = {"rule_name", "outcome", "reason"}
        for name in ("evaluation_trace.allow", "evaluation_trace.deny"):
            fixture = load_fixture(name)
            for rule in fixture["evaluated_rules"]:
                assert set(rule.keys()) == expected_fields, (
                    f"Rule entry in {name!r} has unexpected fields: {set(rule.keys())}. "
                    f"Expected: {expected_fields}"
                )


# ---------------------------------------------------------------------------
# Fixture inventory
# ---------------------------------------------------------------------------


class TestFixtureInventory:
    """The fixture directory contains exactly the expected set of files."""

    EXPECTED_FIXTURES = frozenset(
        {
            "audit_event.allow",
            "audit_event.deny",
            "decision_request.allow",
            "decision_request.deny",
            "decision_response.allow",
            "decision_response.deny",
            "evaluation_trace.allow",
            "evaluation_trace.deny",
        }
    )

    def test_fixture_inventory_is_complete(self) -> None:
        """No fixtures have been added or removed without updating this snapshot."""
        actual = frozenset(fixture_names())
        assert actual == self.EXPECTED_FIXTURES, (
            f"Fixture inventory changed.\n"
            f"  Added:   {actual - self.EXPECTED_FIXTURES}\n"
            f"  Removed: {self.EXPECTED_FIXTURES - actual}\n"
            "Update EXPECTED_FIXTURES in TestFixtureInventory if the change is intentional."
        )

    def test_all_fixtures_are_valid_json_objects(self) -> None:
        """Every fixture file parses as a JSON object."""
        from tests.helpers.contracts import load_fixture

        for name in fixture_names():
            fixture = load_fixture(name)
            assert isinstance(fixture, dict), (
                f"Fixture {name!r} did not parse as a JSON object (dict)."
            )
