"""
Tests for basis_core.policy.rules and deny-overrides PolicyEngine semantics.

Covers:
  - RolePolicyRule: ALLOW, DENY, NOT_APPLICABLE outcomes
  - ResourceTypePolicyRule: permitted/denied types, no resource_id
  - ActionPolicyRule: explicit allowlist, explicit denylist, unregistered actions
  - PolicyEngine deny-overrides: DENY beats ALLOW, default deny, NOT_APPLICABLE
  - PolicyEngine statelesness (successive calls are independent)
  - Import boundary: policy must not import api, audit, or adapters
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from basis_core.domain.resource import ResourceType
from basis_core.domain.subject import Subject, SubjectType
from basis_core.policy.engine import Decision, PolicyEngine, PolicyOutcome
from basis_core.policy.rules import ActionPolicyRule, ResourceTypePolicyRule, RolePolicyRule

# ── Shared fixtures ─────────────────────────────────────────────────────────────


def make_subject(roles: list[str] | None = None) -> Subject:
    return Subject(
        id="test-subject",
        name="test-subject",
        type=SubjectType.HUMAN,
        roles=roles or [],
    )


# ── RolePolicyRule ──────────────────────────────────────────────────────────────


class TestRolePolicyRule:
    ROLE_TABLE: dict[str, set[str]] = {
        "write:hvac:setpoint": {"operator", "admin"},
        "read:audit:log": {"admin"},
        "read:resources": {"viewer", "operator", "admin"},
    }

    def rule(self) -> RolePolicyRule:
        return RolePolicyRule(self.ROLE_TABLE)

    def test_allows_subject_with_permitted_role(self) -> None:
        result = self.rule().evaluate(make_subject(["operator"]), "write:hvac:setpoint")
        assert result.outcome == PolicyOutcome.ALLOW
        assert result.allowed is True

    def test_allows_admin_on_admin_only_action(self) -> None:
        result = self.rule().evaluate(make_subject(["admin"]), "read:audit:log")
        assert result.outcome == PolicyOutcome.ALLOW

    def test_allows_viewer_on_read_action(self) -> None:
        result = self.rule().evaluate(make_subject(["viewer"]), "read:resources")
        assert result.outcome == PolicyOutcome.ALLOW

    def test_denies_subject_without_required_role(self) -> None:
        result = self.rule().evaluate(make_subject(["viewer"]), "write:hvac:setpoint")
        assert result.outcome == PolicyOutcome.DENY
        assert result.allowed is False

    def test_denies_operator_on_admin_only_action(self) -> None:
        result = self.rule().evaluate(make_subject(["operator"]), "read:audit:log")
        assert result.outcome == PolicyOutcome.DENY

    def test_denies_subject_with_no_roles(self) -> None:
        result = self.rule().evaluate(make_subject([]), "write:hvac:setpoint")
        assert result.outcome == PolicyOutcome.DENY

    def test_not_applicable_for_unregistered_action(self) -> None:
        result = self.rule().evaluate(make_subject(["admin"]), "unknown:action:x")
        assert result.outcome == PolicyOutcome.NOT_APPLICABLE
        assert result.allowed is False

    def test_deny_reason_names_required_and_held_roles(self) -> None:
        result = self.rule().evaluate(make_subject(["viewer"]), "write:hvac:setpoint")
        assert "operator" in result.reason or "admin" in result.reason
        assert "viewer" in result.reason

    def test_allow_reason_is_present(self) -> None:
        result = self.rule().evaluate(make_subject(["operator"]), "write:hvac:setpoint")
        assert result.reason

    def test_evaluated_by_defaults_to_class_name(self) -> None:
        result = self.rule().evaluate(make_subject(["operator"]), "write:hvac:setpoint")
        assert result.evaluated_by == "RolePolicyRule"

    def test_custom_rule_name_appears_in_evaluated_by(self) -> None:
        rule = RolePolicyRule(self.ROLE_TABLE, rule_name="SiteARolePolicy")
        result = rule.evaluate(make_subject(["operator"]), "write:hvac:setpoint")
        assert result.evaluated_by == "SiteARolePolicy"

    def test_resource_id_is_accepted_but_not_used(self) -> None:
        """RolePolicyRule does not use resource_id — outcome is the same either way."""
        rule = self.rule()
        with_resource = rule.evaluate(
            make_subject(["operator"]), "write:hvac:setpoint", resource_id="hvac:zone-a"
        )
        without_resource = rule.evaluate(make_subject(["operator"]), "write:hvac:setpoint")
        assert with_resource.outcome == without_resource.outcome


# ── ResourceTypePolicyRule ──────────────────────────────────────────────────────


class TestResourceTypePolicyRule:
    def rule(self) -> ResourceTypePolicyRule:
        return ResourceTypePolicyRule(permitted_types={ResourceType.HVAC})

    def test_allows_permitted_resource_type(self) -> None:
        result = self.rule().evaluate(
            make_subject(["operator"]),
            "write:hvac:setpoint",
            resource_id="hvac:zone-a",
        )
        assert result.outcome == PolicyOutcome.ALLOW

    def test_denies_non_permitted_resource_type(self) -> None:
        result = self.rule().evaluate(
            make_subject(["operator"]),
            "write:hvac:setpoint",
            resource_id="device:chiller-1",
        )
        assert result.outcome == PolicyOutcome.DENY

    def test_denies_sensor_resource_when_only_hvac_permitted(self) -> None:
        result = self.rule().evaluate(
            make_subject(["admin"]),
            "read:sensor:telemetry",
            resource_id="sensor:co2:lobby",
        )
        assert result.outcome == PolicyOutcome.DENY

    def test_not_applicable_when_no_resource_id(self) -> None:
        result = self.rule().evaluate(
            make_subject(["operator"]),
            "write:hvac:setpoint",
            resource_id=None,
        )
        assert result.outcome == PolicyOutcome.NOT_APPLICABLE

    def test_deny_reason_names_disallowed_type(self) -> None:
        result = self.rule().evaluate(
            make_subject(["operator"]),
            "write:device:setpoint",
            resource_id="device:chiller-1",
        )
        assert "device" in result.reason
        assert "hvac" in result.reason

    def test_multiple_permitted_types(self) -> None:
        rule = ResourceTypePolicyRule(permitted_types={ResourceType.HVAC, ResourceType.SENSOR})
        assert (
            rule.evaluate(
                make_subject(), "read:sensor:telemetry", resource_id="sensor:co2:lobby"
            ).outcome
            == PolicyOutcome.ALLOW
        )
        assert (
            rule.evaluate(make_subject(), "read:hvac:state", resource_id="hvac:zone-a").outcome
            == PolicyOutcome.ALLOW
        )
        assert (
            rule.evaluate(
                make_subject(), "read:device:state", resource_id="device:chiller-1"
            ).outcome
            == PolicyOutcome.DENY
        )

    def test_custom_rule_name(self) -> None:
        rule = ResourceTypePolicyRule(
            permitted_types={ResourceType.HVAC},
            rule_name="HVACOnlyRule",
        )
        result = rule.evaluate(make_subject(), "write:hvac:setpoint", resource_id="hvac:zone-a")
        assert result.evaluated_by == "HVACOnlyRule"


# ── ActionPolicyRule ────────────────────────────────────────────────────────────


class TestActionPolicyRule:
    def allowlist_rule(self) -> ActionPolicyRule:
        return ActionPolicyRule(
            {
                "read:sensor:telemetry": PolicyOutcome.ALLOW,
                "read:hvac:state": PolicyOutcome.ALLOW,
            }
        )

    def denylist_rule(self) -> ActionPolicyRule:
        return ActionPolicyRule(
            {
                "write:policy": PolicyOutcome.DENY,
                "read:audit:log": PolicyOutcome.DENY,
            }
        )

    def test_allows_explicitly_allowed_action(self) -> None:
        result = self.allowlist_rule().evaluate(make_subject(["viewer"]), "read:sensor:telemetry")
        assert result.outcome == PolicyOutcome.ALLOW

    def test_denies_explicitly_denied_action(self) -> None:
        result = self.denylist_rule().evaluate(make_subject(["operator"]), "write:policy")
        assert result.outcome == PolicyOutcome.DENY

    def test_not_applicable_for_unregistered_action(self) -> None:
        result = self.allowlist_rule().evaluate(make_subject(["admin"]), "write:hvac:setpoint")
        assert result.outcome == PolicyOutcome.NOT_APPLICABLE

    def test_allow_reason_is_present(self) -> None:
        result = self.allowlist_rule().evaluate(make_subject(), "read:hvac:state")
        assert result.reason

    def test_deny_reason_is_present(self) -> None:
        result = self.denylist_rule().evaluate(make_subject(), "write:policy")
        assert result.reason

    def test_evaluated_by_defaults_to_class_name(self) -> None:
        result = self.allowlist_rule().evaluate(make_subject(), "read:sensor:telemetry")
        assert result.evaluated_by == "ActionPolicyRule"

    def test_custom_rule_name(self) -> None:
        rule = ActionPolicyRule(
            {"write:policy": PolicyOutcome.DENY},
            rule_name="GlobalDenylist",
        )
        result = rule.evaluate(make_subject(), "write:policy")
        assert result.evaluated_by == "GlobalDenylist"


# ── PolicyEngine deny-overrides semantics ──────────────────────────────────────


class TestPolicyEngineDenyOverrides:
    def test_allow_when_matching_allow_rule(self) -> None:
        engine = PolicyEngine(
            policies=[
                RolePolicyRule({"write:hvac:setpoint": {"operator"}}),
            ]
        )
        result = engine.evaluate(make_subject(["operator"]), "write:hvac:setpoint")
        assert result.outcome == PolicyOutcome.ALLOW

    def test_deny_when_matching_deny_rule(self) -> None:
        engine = PolicyEngine(
            policies=[
                RolePolicyRule({"write:hvac:setpoint": {"operator"}}),
            ]
        )
        result = engine.evaluate(make_subject(["viewer"]), "write:hvac:setpoint")
        assert result.outcome == PolicyOutcome.DENY

    def test_deny_overrides_allow(self) -> None:
        """A DENY from any rule wins, regardless of rule order."""
        allow_rule = ActionPolicyRule({"write:hvac:setpoint": PolicyOutcome.ALLOW})
        deny_rule = RolePolicyRule({"write:hvac:setpoint": {"operator"}})
        # allow_rule first: ALLOW. deny_rule second: DENY for viewer. DENY must win.
        engine = PolicyEngine(policies=[allow_rule, deny_rule])
        result = engine.evaluate(make_subject(["viewer"]), "write:hvac:setpoint")
        assert result.outcome == PolicyOutcome.DENY

    def test_deny_overrides_allow_reversed_order(self) -> None:
        """Verify deny-overrides holds when DENY rule appears before ALLOW rule."""
        deny_rule = RolePolicyRule({"write:hvac:setpoint": {"operator"}})
        allow_rule = ActionPolicyRule({"write:hvac:setpoint": PolicyOutcome.ALLOW})
        engine = PolicyEngine(policies=[deny_rule, allow_rule])
        result = engine.evaluate(make_subject(["viewer"]), "write:hvac:setpoint")
        assert result.outcome == PolicyOutcome.DENY

    def test_default_deny_when_no_rule_applies(self) -> None:
        engine = PolicyEngine(
            policies=[
                RolePolicyRule({"write:hvac:setpoint": {"operator"}}),
            ]
        )
        result = engine.evaluate(make_subject(["admin"]), "completely:unknown:action")
        assert result.outcome == PolicyOutcome.NOT_APPLICABLE
        assert result.allowed is False
        assert "PolicyEngine" in result.evaluated_by

    def test_default_deny_with_empty_policy_list(self) -> None:
        engine = PolicyEngine(policies=[])
        result = engine.evaluate(make_subject(["admin"]), "read:audit:log")
        assert result.outcome == PolicyOutcome.NOT_APPLICABLE
        assert result.allowed is False

    def test_not_applicable_is_handled_correctly(self) -> None:
        """NOT_APPLICABLE from all rules → engine default (not_applicable), not an error."""
        rule = RolePolicyRule({"write:hvac:setpoint": {"operator"}})
        engine = PolicyEngine(policies=[rule])
        # "read:sensor:telemetry" is not in the role table → NOT_APPLICABLE
        result = engine.evaluate(make_subject(["operator"]), "read:sensor:telemetry")
        assert result.outcome == PolicyOutcome.NOT_APPLICABLE
        assert result.allowed is False

    def test_resource_type_deny_overrides_role_allow(self) -> None:
        """ResourceTypePolicyRule DENY overrides RolePolicyRule ALLOW."""
        engine = PolicyEngine(
            policies=[
                ResourceTypePolicyRule(permitted_types={ResourceType.HVAC}),
                RolePolicyRule({"write:device:setpoint": {"operator", "admin"}}),
            ]
        )
        # Operator has the role, but the resource is a 'device' (not HVAC) → DENY
        result = engine.evaluate(
            make_subject(["operator"]),
            "write:device:setpoint",
            resource_id="device:chiller-1",
        )
        assert result.outcome == PolicyOutcome.DENY

    def test_both_allow_returns_first_allow(self) -> None:
        """When multiple rules ALLOW, the first ALLOW's evaluated_by is used."""
        rule1 = ActionPolicyRule({"read:resources": PolicyOutcome.ALLOW}, rule_name="AllowRule1")
        rule2 = ActionPolicyRule({"read:resources": PolicyOutcome.ALLOW}, rule_name="AllowRule2")
        engine = PolicyEngine(policies=[rule1, rule2])
        result = engine.evaluate(make_subject(), "read:resources")
        assert result.outcome == PolicyOutcome.ALLOW
        assert result.evaluated_by == "AllowRule1"

    def test_engine_is_stateless(self) -> None:
        """Successive calls return independent decisions; engine holds no per-call state."""
        engine = PolicyEngine(
            policies=[
                RolePolicyRule({"write:hvac:setpoint": {"operator"}}),
            ]
        )
        result_a = engine.evaluate(make_subject(["operator"]), "write:hvac:setpoint")
        result_b = engine.evaluate(make_subject(["viewer"]), "write:hvac:setpoint")
        result_c = engine.evaluate(make_subject(["operator"]), "write:hvac:setpoint")
        assert result_a.outcome == PolicyOutcome.ALLOW
        assert result_b.outcome == PolicyOutcome.DENY
        assert result_c.outcome == PolicyOutcome.ALLOW

    def test_engine_passes_context_to_rules(self) -> None:
        """Rules that inspect the context dict receive the dict from the engine."""

        class ContextCheckingRule:
            def __init__(self) -> None:
                self.received_context: dict[str, Any] | None = None

            def evaluate(
                self,
                subject: Subject,
                action: str,
                resource_id: str | None = None,
                identity_context: object = None,
                context: dict[str, Any] | None = None,
            ) -> Decision:
                self.received_context = context
                return Decision(
                    outcome=PolicyOutcome.NOT_APPLICABLE,
                    reason="no opinion",
                    evaluated_by="ContextCheckingRule",
                )

        checker = ContextCheckingRule()
        engine = PolicyEngine(policies=[checker])
        ctx = {"site": "bldg-a", "maintenance_window": "true"}
        engine.evaluate(make_subject(), "read:resources", context=ctx)
        assert checker.received_context == ctx


# ── Import boundary: policy must not import api, audit, or adapters ────────────


class TestPolicyImportBoundaries:
    """
    Statically verify that the policy package does not import from api, audit,
    or adapters. Uses ast.parse() — no module execution required.
    """

    POLICY_DIR = Path(__file__).parent.parent / "src" / "basis_core" / "policy"

    def _collect_imports(self, path: Path) -> list[str]:
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

    def _all_policy_imports(self) -> list[str]:
        imports: list[str] = []
        for path in self.POLICY_DIR.glob("*.py"):
            imports.extend(self._collect_imports(path))
        return imports

    def test_policy_does_not_import_from_enforcement(self) -> None:
        imports = self._all_policy_imports()
        enf_imports = [m for m in imports if "basis_core.enforcement" in m]
        assert enf_imports == [], f"policy imports from enforcement: {enf_imports}"

    def test_policy_does_not_import_from_audit(self) -> None:
        imports = self._all_policy_imports()
        audit_imports = [m for m in imports if "basis_core.audit" in m]
        assert audit_imports == [], f"policy imports from audit: {audit_imports}"

    def test_policy_does_not_import_from_adapters(self) -> None:
        imports = self._all_policy_imports()
        adapter_imports = [m for m in imports if "basis_core.adapters" in m]
        assert adapter_imports == [], f"policy imports from adapters: {adapter_imports}"

    def test_policy_does_not_import_from_decisions(self) -> None:
        imports = self._all_policy_imports()
        decision_imports = [m for m in imports if "basis_core.decisions" in m]
        assert decision_imports == [], f"policy imports from decisions: {decision_imports}"

    def test_policy_engine_does_not_import_rules(self) -> None:
        """engine.py must not import from rules.py — that would be a circular dependency."""
        engine_path = self.POLICY_DIR / "engine.py"
        imports = self._collect_imports(engine_path)
        rules_imports = [m for m in imports if "basis_core.policy.rules" in m]
        assert rules_imports == [], f"engine.py imports from rules: {rules_imports}"
