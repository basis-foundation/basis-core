"""
examples/basic_evaluation.py — minimal end-to-end authorization evaluation.

Demonstrates the integration boundary: the application constructs a Subject
(from pre-verified identity), submits a DecisionRequest to an EnforcementPoint,
and inspects the DecisionResponse. The kernel handles policy evaluation, the
fail-closed guarantee, and the audit trail.

This example uses only the stable public API. No transport, database, identity
provider, or protocol adapter is required.

Run:
    cd basis-core
    python -m examples.basic_evaluation
"""

from __future__ import annotations

from basis_core.audit import LogAuditWriter
from basis_core.decisions import DecisionRequest
from basis_core.domain import Subject
from basis_core.enforcement import EnforcementPoint
from basis_core.policy import PolicyEngine, RolePolicyRule

# ── Policy configuration ──────────────────────────────────────────────────────

ROLE_TABLE: dict[str, set[str]] = {
    "write:hvac:setpoint": {"operator", "admin"},
    "read:sensor:telemetry": {"viewer", "operator", "admin"},
    "read:audit:log": {"admin"},
}

# ── Assemble the enforcement point ────────────────────────────────────────────

engine = PolicyEngine(policies=[RolePolicyRule(ROLE_TABLE)])
writer = LogAuditWriter()
ep = EnforcementPoint(engine=engine, audit_writer=writer, policy_version="example-v1")


# ── Evaluate some requests ────────────────────────────────────────────────────


def evaluate(name: str, roles: list[str], action: str, resource: str) -> None:
    subject = Subject(id=f"id-{name}", name=name, roles=roles)
    request = DecisionRequest(
        subject_id=subject.id,
        subject_roles=subject.roles,
        resource_id=resource,
        action=action,
    )
    response = ep.evaluate(request, subject=subject)
    verdict = "ALLOW" if response.allowed else "DENY"
    print(f"  [{verdict}] {name!r} → {action!r} on {resource!r}")
    print(f"          reason: {response.reason}")
    print()


if __name__ == "__main__":
    print("basis-core: basic evaluation example\n")

    evaluate("alice", ["operator"], "write:hvac:setpoint", "hvac:zone-a")
    evaluate("bob", ["viewer"], "write:hvac:setpoint", "hvac:zone-a")
    evaluate("carol", ["admin"], "read:audit:log", "audit:log")
    evaluate("dave", ["viewer"], "read:sensor:telemetry", "sensor:co2")
    evaluate("eve", ["operator"], "read:audit:log", "audit:log")
