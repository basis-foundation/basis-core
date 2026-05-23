"""
basis_core.api.enforcement — RENAMED to basis_core.enforcement.enforcement.

This module has been renamed. Import from basis_core.enforcement.enforcement instead:

    from basis_core.enforcement.enforcement import EnforcementPoint

This stub is retained only because the file cannot be deleted from the sandbox.
"""

# Re-export for backward compatibility during transition.
from basis_core.enforcement.enforcement import EnforcementPoint

__all__ = ["EnforcementPoint"]
