"""
basis_core.api — entry points for exposing core authorization logic.

This package is where infrastructure concerns are introduced. HTTP frameworks,
authentication middleware, route handlers, and server configuration belong here.
Nothing in domain/, policy/, decisions/, audit/, or adapters/ imports from api/.

The api/ package is kept minimal in this initial release. It defines the
interface contracts that concrete implementations must satisfy; it does not
introduce FastAPI, databases, or any other infrastructure dependency yet.
Those are added when a deployment-specific transport layer is implemented.

Contents
────────
  enforcement.py   EnforcementPoint — the component that connects incoming
                   requests to the policy engine and audit writer.
"""
