"""
basis_core.domain.action — action vocabulary for authorization requests.

An action is the specific operation a subject is requesting on a resource.
Action names are stable identifiers: they appear verbatim in audit records,
policy rules, and decision responses. Renaming an action breaks audit trail
continuity across the rename boundary.

Naming convention
─────────────────
  "<verb>:<domain>[:<object>]"  — colon-separated, lowercase

  verb:    read | write | execute | subscribe | command
  domain:  resource domain or system area
  object:  specific resource subtype if needed

  Examples:
    "read:sensor:telemetry"      read telemetry from a sensor
    "write:hvac:setpoint"        write a setpoint to an HVAC controller
    "execute:device:command"     execute a command on a generic device
    "subscribe:telemetry"        subscribe to a real-time telemetry stream
    "read:audit:log"             query the audit log

Action vs. role
───────────────
Endpoints declare *what they do* using action names. The policy layer decides
*who may do it* using role and attribute mappings. This separation means that
adding a new role that can perform existing actions requires one change in the
policy configuration — not a change to every endpoint that performs that action.

Stability requirement
─────────────────────
Action names are external identifiers. They appear in audit records that may
outlive the code that generates them. Once an action name is in production use:
  - Do not rename it.
  - To deprecate an action, leave the old name and add the new one alongside it.
  - Document the deprecation date and the replacement action name.
"""

from __future__ import annotations

# ── Telemetry ──────────────────────────────────────────────────────────────────

READ_SENSOR_TELEMETRY = "read:sensor:telemetry"
SUBSCRIBE_TELEMETRY = "subscribe:telemetry"
DISCONNECT_TELEMETRY = "disconnect:telemetry"  # Audit-record only; not enforced

# ── HVAC control ──────────────────────────────────────────────────────────────

READ_HVAC_STATE = "read:hvac:state"
WRITE_HVAC_SETPOINT = "write:hvac:setpoint"
WRITE_HVAC_MODE = "write:hvac:mode"

# ── Generic device commands ───────────────────────────────────────────────────

READ_DEVICE_STATE = "read:device:state"
WRITE_DEVICE_SETPOINT = "write:device:setpoint"
EXECUTE_DEVICE_COMMAND = "execute:device:command"

# ── Zone operations ───────────────────────────────────────────────────────────

READ_ZONE_STATE = "read:zone:state"

# ── Resource registry ─────────────────────────────────────────────────────────

READ_RESOURCES = "read:resources"

# ── Audit log ─────────────────────────────────────────────────────────────────

READ_AUDIT_LOG = "read:audit:log"

# ── Identity and policy management ────────────────────────────────────────────

READ_POLICY = "read:policy"
WRITE_POLICY = "write:policy"
